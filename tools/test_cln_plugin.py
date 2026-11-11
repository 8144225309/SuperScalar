#!/usr/bin/env python3
"""Unit tests for the SuperScalar CLN plugin (tools/cln_plugin.py).

The CLN RPC and the bridge socket are mocked; no Lightning node is needed.

Run:  python3 -m unittest tools/test_cln_plugin.py
"""

import hashlib
import os
import json
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cln_plugin  # noqa: E402

PREIMAGE = "11" * 32
PAYMENT_HASH = hashlib.sha256(bytes.fromhex(PREIMAGE)).hexdigest()
OTHER_HASH = "ab" * 32
BOLT11 = "lnbcrt40u1pexampleinvoice"


def decoded_invoice(amount_msat=4_000_000, payment_hash=PAYMENT_HASH, **extra):
    """What CLN's `decode` returns for a bolt11 invoice (fields we use)."""
    d = {"type": "bolt11 invoice", "valid": True, "payment_hash": payment_hash}
    if amount_msat is not None:
        d["amount_msat"] = amount_msat
    d.update(extra)
    return d


class FakeCln:
    """Stands in for cln_plugin.cln_rpc: answers each RPC method from a
    scripted list of replies (the last reply repeats) and records calls."""

    def __init__(self, **replies):
        self.replies = {m: list(r) if isinstance(r, list) else [r]
                        for m, r in replies.items()}
        self.calls = []

    def __call__(self, method, params=None, timeout=60):
        self.calls.append((method, dict(params or {})))
        if method not in self.replies:
            raise AssertionError(f"unexpected CLN call: {method}")
        queue = self.replies[method]
        reply = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(reply, BaseException):
            raise reply
        return reply

    def calls_to(self, method):
        return [p for m, p in self.calls if m == method]


class PluginTestCase(unittest.TestCase):
    """Resets plugin state and captures everything sent to the bridge/CLN."""

    def setUp(self):
        self.to_bridge = []
        self.to_cln = []
        for target, repl in (
            ("send_to_bridge", lambda msg: self.to_bridge.append(msg) or True),
            ("send_to_cln", self.to_cln.append),
            ("log", lambda msg: None),
        ):
            p = mock.patch.object(cln_plugin, target, repl)
            p.start()
            self.addCleanup(p.stop)
        # The clock is always faked, so a pay that keeps polling fails the
        # test instead of sleeping.
        self.sleeps = self.install_clock()
        cln_plugin.pending_htlcs.clear()
        cln_plugin.pending_pays.clear()
        cln_plugin.registered_invoices.clear()
        p = mock.patch.object(cln_plugin, "registry_recovered", True)
        p.start()
        self.addCleanup(p.stop)

    def use_cln(self, **replies):
        fake = FakeCln(**replies)
        p = mock.patch.object(cln_plugin, "cln_rpc", fake)
        p.start()
        self.addCleanup(p.stop)
        return fake

    def install_clock(self):
        """Replace the plugin's clock: sleeping advances it instantly.
        Returns the list of sleeps taken."""
        clock = {"now": 1000.0}
        sleeps = []

        def fake_sleep(seconds):
            sleeps.append(seconds)
            clock["now"] += seconds
            if len(sleeps) > 500:
                raise AssertionError("plugin never stopped polling")

        for name, repl in (("sleep", fake_sleep),
                           ("monotonic", lambda: clock["now"])):
            p = mock.patch.object(cln_plugin.time, name, repl)
            p.start()
            self.addCleanup(p.stop)
        return sleeps

    def pay_results(self):
        return [m for m in self.to_bridge if m.get("method") == "pay_result"]

    def assert_pay_failed(self, request_id):
        results = self.pay_results()
        self.assertEqual(len(results), 1, results)
        self.assertEqual(results[0]["request_id"], request_id)
        self.assertIs(results[0]["success"], False)


class CheckPayRequestTest(unittest.TestCase):
    def test_matching_invoice_is_accepted(self):
        amount, why = cln_plugin.check_pay_request(
            decoded_invoice(4_000_000), PAYMENT_HASH, 4_000_000, 144)
        self.assertIsNone(why)
        self.assertEqual(amount, 4_000_000)

    def test_amount_as_msat_string(self):
        amount, why = cln_plugin.check_pay_request(
            decoded_invoice("4000000msat"), PAYMENT_HASH, 4_100_000, 144)
        self.assertIsNone(why)
        self.assertEqual(amount, 4_000_000)

    def test_hash_comparison_ignores_case(self):
        amount, why = cln_plugin.check_pay_request(
            decoded_invoice(1000, payment_hash=PAYMENT_HASH.upper()),
            PAYMENT_HASH, 1000, 144)
        self.assertIsNone(why)

    def test_other_payment_hash_is_refused(self):
        amount, why = cln_plugin.check_pay_request(
            decoded_invoice(4_000_000, payment_hash=OTHER_HASH),
            PAYMENT_HASH, 4_000_000, 144)
        self.assertIsNone(amount)
        self.assertIn("payment hash", why)

    def test_amount_above_cap_is_refused(self):
        amount, why = cln_plugin.check_pay_request(
            decoded_invoice(4_000_001), PAYMENT_HASH, 4_000_000, 144)
        self.assertIsNone(amount)
        self.assertIn("exceeds", why)

    def test_amountless_invoice_is_refused(self):
        for decoded in (decoded_invoice(None), decoded_invoice(0)):
            amount, why = cln_plugin.check_pay_request(
                decoded, PAYMENT_HASH, 4_000_000, 144)
            self.assertIsNone(amount)
            self.assertIn("no amount", why)

    def test_request_without_hash_or_cap_is_refused(self):
        for payment_hash, cap in ((None, 4_000_000), ("", 4_000_000),
                                  ("00", 4_000_000), (PAYMENT_HASH, None),
                                  (PAYMENT_HASH, 0), (PAYMENT_HASH, -5),
                                  (PAYMENT_HASH, "4000000"),
                                  (PAYMENT_HASH, True)):
            amount, why = cln_plugin.check_pay_request(
                decoded_invoice(1000), payment_hash, cap, 144)
            self.assertIsNone(amount, (payment_hash, cap))
            self.assertTrue(why)

    def test_request_without_delay_bound_is_refused(self):
        for max_delay in (None, 0, -1, "144", True):
            amount, why = cln_plugin.check_pay_request(
                decoded_invoice(1000), PAYMENT_HASH, 4_000_000, max_delay)
            self.assertIsNone(amount, max_delay)
            self.assertIn("delay", why)

    def test_final_hop_longer_than_the_delay_bound_is_refused(self):
        amount, why = cln_plugin.check_pay_request(
            decoded_invoice(1000, min_final_cltv_expiry=145),
            PAYMENT_HASH, 4_000_000, 144)
        self.assertIsNone(amount)
        self.assertIn("final-hop", why)
        amount, why = cln_plugin.check_pay_request(
            decoded_invoice(1000, min_final_cltv_expiry=144),
            PAYMENT_HASH, 4_000_000, 144)
        self.assertIsNone(why)

    def test_non_invoice_is_refused(self):
        for decoded in (None, {}, {"valid": False, "type": "bolt11 invoice"},
                        decoded_invoice(1000, type="bolt12 offer"),
                        decoded_invoice(1000, valid="true")):
            amount, why = cln_plugin.check_pay_request(
                decoded, PAYMENT_HASH, 4_000_000, 144)
            self.assertIsNone(amount, decoded)


class OutboundPayTest(PluginTestCase):
    def test_pay_is_capped_by_the_request(self):
        cln = self.use_cln(
            decode=decoded_invoice(3_990_000),
            pay={"status": "complete", "payment_preimage": PREIMAGE})
        cln_plugin._do_pay(BOLT11, 7, PAYMENT_HASH, 4_000_000, 144)

        self.assertEqual(cln.calls_to("decode"), [{"string": BOLT11}])
        pays = cln.calls_to("pay")
        self.assertEqual(len(pays), 1)
        self.assertEqual(pays[0]["bolt11"], BOLT11)
        # Invoice 3,990,000 of a 4,000,000 cap leaves 10,000 for routing fees.
        self.assertEqual(pays[0]["maxfee"], 10_000)
        # The route may not lock the payment up for longer than allowed.
        self.assertEqual(pays[0]["maxdelay"], 144)
        self.assertEqual(pays[0]["retry_for"], cln_plugin.PAY_RETRY_FOR)
        self.assertEqual(self.pay_results(), [{
            "method": "pay_result", "request_id": 7, "success": True,
            "preimage": PREIMAGE}])

    def test_invoice_at_the_cap_leaves_no_fee_budget(self):
        cln = self.use_cln(
            decode=decoded_invoice(4_000_000),
            pay={"status": "complete", "payment_preimage": PREIMAGE})
        cln_plugin._do_pay(BOLT11, 7, PAYMENT_HASH, 4_000_000, 144)
        self.assertEqual(cln.calls_to("pay")[0]["maxfee"], 0)

    def test_invoice_for_another_hash_is_never_paid(self):
        cln = self.use_cln(decode=decoded_invoice(1000, payment_hash=OTHER_HASH))
        cln_plugin._do_pay(BOLT11, 8, PAYMENT_HASH, 4_000_000, 144)
        self.assertEqual(cln.calls_to("pay"), [])
        self.assert_pay_failed(8)

    def test_invoice_above_the_cap_is_never_paid(self):
        cln = self.use_cln(decode=decoded_invoice(4_000_000_000))
        cln_plugin._do_pay(BOLT11, 9, PAYMENT_HASH, 4_000_000, 144)
        self.assertEqual(cln.calls_to("pay"), [])
        self.assert_pay_failed(9)

    def test_amountless_invoice_is_never_paid(self):
        cln = self.use_cln(decode=decoded_invoice(None))
        cln_plugin._do_pay(BOLT11, 10, PAYMENT_HASH, 4_000_000, 144)
        self.assertEqual(cln.calls_to("pay"), [])
        self.assert_pay_failed(10)

    def test_request_without_limits_is_never_paid(self):
        cln = self.use_cln(decode=decoded_invoice(1000))
        cln_plugin._do_pay(BOLT11, 11, None, None, None)
        self.assertEqual(cln.calls_to("pay"), [])
        self.assert_pay_failed(11)

    def test_undecodable_invoice_is_never_paid(self):
        cln = self.use_cln(
            decode=cln_plugin.ClnRpcError("Invalid bolt11", code=-32602))
        cln_plugin._do_pay("garbage", 12, PAYMENT_HASH, 4_000_000, 144)
        self.assertEqual(cln.calls_to("pay"), [])
        self.assert_pay_failed(12)

    def test_bridge_request_passes_hash_and_cap_to_pay(self):
        started = []

        class InlineThread:
            def __init__(self, target, args=(), daemon=None):
                self.target, self.args = target, args

            def start(self):
                started.append(self.args)

        with mock.patch.object(cln_plugin.threading, "Thread", InlineThread):
            cln_plugin.handle_bridge_msg({
                "method": "pay_request", "bolt11": BOLT11, "request_id": 3,
                "payment_hash": PAYMENT_HASH, "max_total_msat": 4_000_000,
                "max_delay": 144})
            cln_plugin.handle_bridge_msg({
                "method": "pay_request", "bolt11": BOLT11, "request_id": 4})
        self.assertEqual(started, [
            (BOLT11, 3, PAYMENT_HASH, 4_000_000, 144),
            (BOLT11, 4, None, None, None)])


def listed(*statuses, preimage=PREIMAGE):
    """A `listpays` reply with one entry per status."""
    pays = []
    for status in statuses:
        entry = {"payment_hash": PAYMENT_HASH, "status": status}
        if status == "complete":
            entry["preimage"] = preimage
        pays.append(entry)
    return {"pays": pays}


PAY_TIMEOUT = subprocess.TimeoutExpired(cmd="lightning-cli pay", timeout=600)


class OutboundPayResolutionTest(PluginTestCase):
    """Failure reaches the bridge only once CLN can no longer complete the
    payment; until then nothing is reported."""

    def pay(self, request_id=20):
        cln_plugin._do_pay(BOLT11, request_id, PAYMENT_HASH, 4_000_000, 144)

    def test_timeout_then_late_success_is_reported_as_success(self):
        sleeps = self.sleeps
        cln = self.use_cln(
            decode=decoded_invoice(4_000_000), pay=PAY_TIMEOUT,
            listpays=[listed("pending"), listed("pending"), listed("complete")])
        self.pay()
        self.assertEqual(len(cln.calls_to("listpays")), 3)
        self.assertEqual(cln.calls_to("listpays")[0],
                         {"payment_hash": PAYMENT_HASH})
        self.assertEqual(sleeps, [cln_plugin.PAY_POLL_INTERVAL] * 2)
        self.assertEqual(self.pay_results(), [{
            "method": "pay_result", "request_id": 20, "success": True,
            "preimage": PREIMAGE}])

    def test_nothing_is_reported_while_the_payment_is_pending(self):
        reported_during_poll = []

        def scripted(method, params=None, timeout=60):
            if method == "decode":
                return decoded_invoice(4_000_000)
            if method == "pay":
                raise PAY_TIMEOUT
            reported_during_poll.append(len(self.pay_results()))
            if len(reported_during_poll) < 40:
                return listed("pending")
            return listed("failed")

        with mock.patch.object(cln_plugin, "cln_rpc", scripted):
            self.pay(21)
        # 40 polls, and not one result sent before the last of them.
        self.assertEqual(reported_during_poll, [0] * 40)
        self.assert_pay_failed(21)

    def test_pending_status_from_pay_is_followed_not_failed(self):
        self.use_cln(
            decode=decoded_invoice(4_000_000), pay={"status": "pending"},
            listpays=[listed("pending"), listed("complete")])
        self.pay(22)
        self.assertEqual(self.pay_results(), [{
            "method": "pay_result", "request_id": 22, "success": True,
            "preimage": PREIMAGE}])

    def test_pay_error_with_parts_in_flight_is_followed(self):
        # 210: pay gave up retrying while an earlier attempt is still out.
        cln = self.use_cln(
            decode=decoded_invoice(4_000_000),
            pay=cln_plugin.ClnRpcError("Stopped retrying", code=210),
            listpays=[listed("failed", "pending"), listed("failed", "complete")])
        self.pay(23)
        self.assertEqual(len(cln.calls_to("listpays")), 2)
        self.assertEqual(self.pay_results(), [{
            "method": "pay_result", "request_id": 23, "success": True,
            "preimage": PREIMAGE}])

    def test_pay_error_with_every_attempt_failed_is_a_failure(self):
        sleeps = self.sleeps
        self.use_cln(
            decode=decoded_invoice(4_000_000),
            pay=cln_plugin.ClnRpcError("Ran out of routes", code=205),
            listpays=listed("failed", "failed"))
        self.pay(24)
        self.assertEqual(sleeps, [])
        self.assert_pay_failed(24)

    def test_pay_error_before_any_attempt_is_a_failure(self):
        sleeps = self.sleeps
        self.use_cln(
            decode=decoded_invoice(4_000_000),
            pay=cln_plugin.ClnRpcError("Could not find a route", code=205),
            listpays=listed())
        self.pay(25)
        self.assertEqual(sleeps, [])
        self.assert_pay_failed(25)

    def test_timeout_does_not_trust_failed_while_pay_may_still_retry(self):
        sleeps = self.sleeps
        # `pay` did not return, so it may be between two attempts: "failed"
        # is only final once its retry window has passed.
        self.use_cln(decode=decoded_invoice(4_000_000), pay=PAY_TIMEOUT,
                     listpays=listed("failed"))
        self.pay(26)
        window = cln_plugin.PAY_RETRY_FOR + cln_plugin.PAY_SETTLE_GRACE
        self.assertGreaterEqual(sum(sleeps), window)
        self.assertLess(sum(sleeps), window + 2 * cln_plugin.PAY_POLL_INTERVAL)
        self.assert_pay_failed(26)

    def test_lost_cli_connection_is_not_a_failure(self):
        # lightning-cli died without a JSON-RPC error: no verdict on the pay.
        self.use_cln(
            decode=decoded_invoice(4_000_000),
            pay=cln_plugin.ClnRpcError("Connection refused", code=None),
            listpays=[listed("pending"), listed("complete")])
        self.pay(27)
        self.assertEqual(self.pay_results()[0]["success"], True)

    def test_unreachable_cln_keeps_the_payment_held(self):
        sleeps = self.sleeps
        self.use_cln(
            decode=decoded_invoice(4_000_000), pay=PAY_TIMEOUT,
            listpays=[cln_plugin.ClnRpcError("Connection refused")] * 30
            + [listed("complete")])
        self.pay(28)
        self.assertEqual(len(sleeps), 30)
        self.assertEqual(self.pay_results(), [{
            "method": "pay_result", "request_id": 28, "success": True,
            "preimage": PREIMAGE}])

    def test_complete_without_the_right_preimage_is_never_a_success(self):
        sleeps = self.sleeps
        self.use_cln(
            decode=decoded_invoice(4_000_000),
            pay={"status": "complete", "payment_preimage": "22" * 32},
            listpays=[listed("complete", preimage="22" * 32)] * 5
            + [listed("complete")])
        self.pay(29)
        # Held (never refunded) until CLN shows the preimage of this hash.
        self.assertEqual(len(sleeps), 5)
        self.assertEqual(self.pay_results(), [{
            "method": "pay_result", "request_id": 29, "success": True,
            "preimage": PREIMAGE}])


def htlc(payment_hash=PAYMENT_HASH, amount_msat=5_000_000, cltv_expiry=500,
         channel=None, htlc_id=None, **onion):
    """htlc_accepted hook parameters.  channel/htlc_id are CLN's name for
    the incoming HTLC.  Extra keywords go into the onion; a short_channel_id
    there makes it a forward."""
    h = {"payment_hash": payment_hash, "amount_msat": amount_msat,
         "cltv_expiry": cltv_expiry}
    if channel is not None:
        h["short_channel_id"] = channel
    if htlc_id is not None:
        h["id"] = htlc_id
    return {"htlc": h, "onion": dict(onion)}


CONTINUE = {"result": "continue"}


def fail(code="2002"):
    return {"result": "fail", "failure_message": code}


class InboundHtlcTest(PluginTestCase):
    """HTLCs for factory invoices are resolved on the LSP's word or failed;
    they are never left for CLN to settle from its own copy of the invoice."""

    def hook_answers(self):
        """(rpc_id, result) for every hook answer sent to CLN."""
        return [(m["id"], m["result"]) for m in self.to_cln if "id" in m]

    def to_lsp(self):
        return [m for m in self.to_bridge if m.get("method") == "htlc_accepted"]

    def register(self, payment_hash=PAYMENT_HASH):
        cln_plugin.registered_invoices.add(payment_hash)

    def lsp_fails(self, reason, payment_hash=PAYMENT_HASH):
        cln_plugin.handle_bridge_msg({
            "method": "htlc_resolve", "payment_hash": payment_hash,
            "htlc_id": 1, "result": "fail", "reason": reason})

    # --- amount ---

    def test_factory_invoice_htlc_goes_to_the_lsp_with_its_amount(self):
        self.register()
        cln_plugin.handle_htlc_accepted(1, htlc(amount_msat=5_000_000,
                                                channel="100x1x0", htlc_id=5))
        self.assertEqual(self.to_lsp(), [{
            "method": "htlc_accepted", "payment_hash": PAYMENT_HASH,
            "amount_msat": 5_000_000, "cltv_expiry": 500,
            "upstream_id": "100x1x0:5"}])
        self.assertEqual(self.hook_answers(), [])   # held until the LSP answers

    def test_amount_is_what_the_htlc_delivers_not_the_onion_forward_amount(self):
        # A sender routes 1 sat through this node while its onion claims a
        # 5,000 sat forward.  Only the 1 sat arrived.
        for claimed in (5_000_000, "5000000msat"):
            self.to_bridge.clear()
            cln_plugin.pending_htlcs.clear()
            cln_plugin.handle_htlc_accepted(2, htlc(
                amount_msat=1000, short_channel_id="1x1x1",
                forward_msat=claimed, outgoing_cltv_value=400))
            self.assertEqual([m["amount_msat"] for m in self.to_lsp()], [1000])

    def test_forward_of_a_registered_hash_reports_the_received_amount(self):
        self.register()
        cln_plugin.handle_htlc_accepted(3, htlc(
            amount_msat="1000msat", short_channel_id="1x1x1",
            forward_msat=5_000_000))
        self.assertEqual([m["amount_msat"] for m in self.to_lsp()], [1000])

    # --- the LSP's answer ---

    def test_fulfil_resolves_the_htlc_and_retires_the_invoice(self):
        self.register()
        cln_plugin.handle_htlc_accepted(4, htlc())
        cln_plugin.handle_bridge_msg({
            "method": "htlc_resolve", "payment_hash": PAYMENT_HASH,
            "htlc_id": 1, "result": "fulfill", "preimage": PREIMAGE})
        self.assertEqual(self.hook_answers(), [
            (4, {"result": "resolve", "payment_key": PREIMAGE})])
        self.assertNotIn(PAYMENT_HASH, cln_plugin.registered_invoices)
        self.assertEqual(cln_plugin.pending_htlcs, {})

    def test_lsp_refusal_fails_the_htlc(self):
        self.register()
        cln_plugin.handle_htlc_accepted(5, htlc(amount_msat=1000))
        self.lsp_fails("amount_below_invoice")
        self.assertEqual(self.hook_answers(), [(5, fail())])

    def test_refused_invoice_stays_registered_for_the_next_attempt(self):
        self.register()
        cln_plugin.handle_htlc_accepted(6, htlc(amount_msat=1000))
        self.lsp_fails("amount_below_invoice")
        self.assertIn(PAYMENT_HASH, cln_plugin.registered_invoices)
        # The retry is offered to the LSP again rather than left to CLN.
        cln_plugin.handle_htlc_accepted(7, htlc(amount_msat=5_000_000))
        self.assertEqual([m["amount_msat"] for m in self.to_lsp()],
                         [1000, 5_000_000])
        self.assertEqual(self.hook_answers(), [(6, fail())])

    def test_factory_invoice_unknown_to_the_lsp_is_failed_not_continued(self):
        self.register()
        cln_plugin.handle_htlc_accepted(8, htlc())
        self.lsp_fails("unknown_payment_hash")
        self.assertEqual(self.hook_answers(), [(8, fail())])
        self.assertIn(PAYMENT_HASH, cln_plugin.registered_invoices)

    def test_forward_unknown_to_the_lsp_is_left_to_cln(self):
        cln_plugin.handle_htlc_accepted(9, htlc(short_channel_id="1x1x1"))
        self.lsp_fails("unknown_payment_hash")
        self.assertEqual(self.hook_answers(), [(9, CONTINUE)])

    def test_forward_refused_by_the_lsp_for_another_reason_is_failed(self):
        cln_plugin.handle_htlc_accepted(10, htlc(short_channel_id="1x1x1"))
        self.lsp_fails("insufficient_funds")
        self.assertEqual(self.hook_answers(), [(10, fail())])

    # --- HTLCs that never reach the LSP ---

    def test_own_invoice_of_the_node_is_left_to_cln(self):
        cln_plugin.handle_htlc_accepted(11, htlc(payment_hash=OTHER_HASH))
        self.assertEqual(self.hook_answers(), [(11, CONTINUE)])
        self.assertEqual(self.to_lsp(), [])

    def test_second_htlc_for_a_factory_invoice_in_flight_is_failed(self):
        self.register()
        cln_plugin.handle_htlc_accepted(12, htlc(amount_msat=2_500_000))
        cln_plugin.handle_htlc_accepted(13, htlc(amount_msat=2_500_000))
        self.assertEqual(self.hook_answers(), [(13, fail("0017"))])
        self.assertEqual(len(self.to_lsp()), 1)
        # The first one is still the LSP's to resolve.
        self.assertEqual(cln_plugin.pending_htlcs[PAYMENT_HASH]["rpc_id"], 12)

    def test_same_htlc_offered_again_is_reattached_not_failed(self):
        self.register()
        cln_plugin.handle_htlc_accepted(30, htlc(channel="100x1x0", htlc_id=5))
        cln_plugin.handle_htlc_accepted(31, htlc(channel="100x1x0", htlc_id=5))
        # Nothing is failed, the LSP is offered it again under the same name,
        self.assertEqual(self.hook_answers(), [])
        self.assertEqual([m["upstream_id"] for m in self.to_lsp()],
                         ["100x1x0:5", "100x1x0:5"])
        # and the LSP's answer goes to the latest hook call.
        cln_plugin.handle_bridge_msg({
            "method": "htlc_resolve", "payment_hash": PAYMENT_HASH,
            "htlc_id": 1, "result": "fulfill", "preimage": PREIMAGE})
        self.assertEqual(self.hook_answers(), [
            (31, {"result": "resolve", "payment_key": PREIMAGE})])

    def test_another_htlc_for_the_hash_is_still_failed(self):
        self.register()
        cln_plugin.handle_htlc_accepted(32, htlc(channel="100x1x0", htlc_id=5))
        cln_plugin.handle_htlc_accepted(33, htlc(channel="100x1x0", htlc_id=6))
        cln_plugin.handle_htlc_accepted(34, htlc(channel="200x2x0", htlc_id=5))
        self.assertEqual(self.hook_answers(), [(33, fail("0017")),
                                               (34, fail("0017"))])
        self.assertEqual(len(self.to_lsp()), 1)
        self.assertEqual(cln_plugin.pending_htlcs[PAYMENT_HASH]["rpc_id"], 32)

    def test_htlcs_cln_does_not_name_are_never_merged(self):
        self.register()
        self.assertEqual(cln_plugin.upstream_id({"payment_hash": "x"}), "")
        self.assertEqual(cln_plugin.upstream_id({"short_channel_id": "1x1x1"}), "")
        self.assertEqual(cln_plugin.upstream_id({"short_channel_id": "1x1x1",
                                                 "id": 0}), "1x1x1:0")
        cln_plugin.handle_htlc_accepted(35, htlc())
        cln_plugin.handle_htlc_accepted(36, htlc())
        self.assertEqual(self.hook_answers(), [(36, fail("0017"))])

    def test_second_htlc_for_a_forward_in_flight_is_left_to_cln(self):
        cln_plugin.handle_htlc_accepted(14, htlc(short_channel_id="1x1x1"))
        cln_plugin.handle_htlc_accepted(15, htlc(short_channel_id="1x1x1"))
        self.assertEqual(self.hook_answers(), [(15, CONTINUE)])

    def test_factory_invoice_is_failed_when_the_bridge_is_down(self):
        self.register()
        with mock.patch.object(cln_plugin, "send_to_bridge", lambda m: False):
            cln_plugin.handle_htlc_accepted(16, htlc())
        self.assertEqual(self.hook_answers(), [(16, fail())])
        self.assertEqual(cln_plugin.pending_htlcs, {})
        self.assertIn(PAYMENT_HASH, cln_plugin.registered_invoices)

    def test_forward_is_left_to_cln_when_the_bridge_is_down(self):
        with mock.patch.object(cln_plugin, "send_to_bridge", lambda m: False):
            cln_plugin.handle_htlc_accepted(17, htlc(short_channel_id="1x1x1"))
        self.assertEqual(self.hook_answers(), [(17, CONTINUE)])

    # --- the registry after a restart ---

    def test_registry_is_rebuilt_from_unpaid_factory_invoices(self):
        cln_plugin.registry_recovered = False
        self.use_cln(listinvoices={"invoices": [
            {"label": "superscalar-aa-1", "status": "unpaid",
             "payment_hash": PAYMENT_HASH},
            {"label": "superscalar-bb-2", "status": "paid",
             "payment_hash": "bb" * 32},
            {"label": "coffee", "status": "unpaid",
             "payment_hash": OTHER_HASH}]})
        self.assertTrue(cln_plugin.recover_registered_invoices())
        self.assertEqual(cln_plugin.registered_invoices, {PAYMENT_HASH})
        self.assertTrue(cln_plugin.registry_recovered)

    def test_unclassifiable_htlc_is_failed_while_the_registry_is_unknown(self):
        cln_plugin.registry_recovered = False
        cln = self.use_cln(listinvoices=[
            cln_plugin.ClnRpcError("Connection refused"),
            {"invoices": [{"label": "superscalar-aa-1", "status": "unpaid",
                           "payment_hash": PAYMENT_HASH}]}])
        # CLN's invoice list cannot be read: this may be a factory invoice.
        cln_plugin.handle_htlc_accepted(18, htlc())
        self.assertEqual(self.hook_answers(), [(18, fail())])
        self.assertEqual(self.to_lsp(), [])
        # Once it can be read, the retry is recognised and sent to the LSP.
        cln_plugin.handle_htlc_accepted(19, htlc())
        self.assertEqual(len(self.to_lsp()), 1)
        self.assertEqual(len(cln.calls_to("listinvoices")), 2)
        # ...and the list is not fetched again after that.
        cln_plugin.handle_htlc_accepted(20, htlc(payment_hash=OTHER_HASH))
        self.assertEqual(len(cln.calls_to("listinvoices")), 2)
        self.assertEqual(self.hook_answers()[-1], (20, CONTINUE))

    # --- bridge reconnect ---

    def test_held_htlcs_stay_held_across_a_bridge_reconnect(self):
        self.register()
        cln_plugin.handle_htlc_accepted(21, htlc())

        class Stop(Exception):
            pass

        connects = []

        def fake_connect():
            connects.append(1)
            if len(connects) > 1:
                raise Stop()
            return True

        with mock.patch.object(cln_plugin, "bridge_sock", None), \
                mock.patch.object(cln_plugin, "connect_bridge", fake_connect), \
                mock.patch.object(cln_plugin.time, "sleep", lambda s: None):
            with self.assertRaises(Stop):
                cln_plugin.bridge_reader()   # disconnect, reconnect, disconnect

        # Nothing was answered to CLN and the HTLC is still the LSP's.
        self.assertEqual(self.hook_answers(), [])
        self.assertEqual(cln_plugin.pending_htlcs[PAYMENT_HASH]["rpc_id"], 21)
        # Its verdict still resolves the HTLC afterwards.
        cln_plugin.handle_bridge_msg({
            "method": "htlc_resolve", "payment_hash": PAYMENT_HASH,
            "htlc_id": 1, "result": "fulfill", "preimage": PREIMAGE})
        self.assertEqual(self.hook_answers(), [
            (21, {"result": "resolve", "payment_key": PREIMAGE})])


class BridgeAuthTest(PluginTestCase):
    """The plugin presents the bridge's shared secret before anything else."""

    SECRET = "5c" * 32

    class FakeSocket:
        def __init__(self):
            self.sent = b""

        def sendall(self, data):
            self.sent += data

    def setUp(self):
        super().setUp()
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.secret_path = os.path.join(self.dir.name, "bridge-plugin.secret")
        for name, value in (("BRIDGE_SECRET_FILE", self.secret_path),
                            ("bridge_sock", None)):
            p = mock.patch.object(cln_plugin, name, value)
            p.start()
            self.addCleanup(p.stop)

    def write_secret(self, text):
        with open(self.secret_path, "w") as f:
            f.write(text)

    def connect(self):
        sock = self.FakeSocket()
        with mock.patch.object(cln_plugin.socket, "create_connection",
                               return_value=sock) as create:
            ok = cln_plugin.connect_bridge()
        return ok, sock, create

    def test_secret_is_the_first_message(self):
        self.write_secret(self.SECRET + "\n")
        ok, sock, create = self.connect()
        self.assertTrue(ok)
        create.assert_called_once()
        first_line, rest = sock.sent.split(b"\n", 1)
        self.assertEqual(json.loads(first_line),
                         {"method": "auth", "token": self.SECRET})
        self.assertEqual(rest, b"")
        self.assertIs(cln_plugin.bridge_sock, sock)

    def test_secret_is_read_again_on_every_connect(self):
        self.write_secret("aa" * 32)
        _, first, _ = self.connect()
        self.write_secret("bb" * 32)
        _, second, _ = self.connect()
        self.assertEqual(json.loads(first.sent)["token"], "aa" * 32)
        self.assertEqual(json.loads(second.sent)["token"], "bb" * 32)

    def test_no_connection_without_a_secret(self):
        ok, sock, create = self.connect()   # file does not exist
        self.assertFalse(ok)
        create.assert_not_called()
        self.assertIsNone(cln_plugin.bridge_sock)

    def test_no_connection_with_a_malformed_secret(self):
        for text in ("", "short", "zz" * 32, "5c" * 33):
            self.write_secret(text)
            ok, sock, create = self.connect()
            self.assertFalse(ok, text)
            create.assert_not_called()
            self.assertEqual(sock.sent, b"")

    def test_home_directory_is_expanded(self):
        with mock.patch.object(cln_plugin, "BRIDGE_SECRET_FILE",
                               "~/bridge-plugin.secret"), \
                mock.patch.dict(os.environ, {"HOME": self.dir.name}):
            self.write_secret(self.SECRET)
            self.assertEqual(cln_plugin.read_bridge_secret(), self.SECRET)


class ClnRpcTest(unittest.TestCase):
    def run_with(self, returncode, stdout, stderr=""):
        completed = subprocess.CompletedProcess([], returncode, stdout, stderr)
        with mock.patch.object(cln_plugin.subprocess, "run",
                               return_value=completed) as run:
            try:
                return cln_plugin.cln_rpc("pay", {"bolt11": BOLT11, "maxfee": 5}), run
            except cln_plugin.ClnRpcError as e:
                return e, run

    def test_keyword_arguments_and_result(self):
        result, run = self.run_with(0, '{"status": "complete"}')
        self.assertEqual(result, {"status": "complete"})
        argv = run.call_args[0][0]
        self.assertEqual(argv[-4:], ["-k", "pay", f"bolt11={BOLT11}", "maxfee=5"])

    def test_error_reply_raises_with_code(self):
        err, _ = self.run_with(1, '{"code": 210, "message": "Ran out of routes"}')
        self.assertIsInstance(err, cln_plugin.ClnRpcError)
        self.assertEqual(err.code, 210)
        self.assertIn("Ran out of routes", str(err))


if __name__ == "__main__":
    unittest.main()

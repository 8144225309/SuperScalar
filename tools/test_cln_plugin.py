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
PREIMAGE2 = "22" * 32
PAYMENT_HASH2 = hashlib.sha256(bytes.fromhex(PREIMAGE2)).hexdigest()
BOLT11 = "lnbcrt40u1pexampleinvoice"
OWN_NODE = "02" + "cd" * 32


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
        # No earlier payment for the hash unless a test says otherwise.
        replies.setdefault("listsendpays", {"payments": []})
        replies.setdefault("getinfo", {"id": OWN_NODE})
        self.replies = {m: list(r) if isinstance(r, list) else [r]
                        for m, r in replies.items()}
        self.calls = []

    def __call__(self, method, params=None, timeout=60):
        self.calls.append((method, dict(params or {})))
        if method not in self.replies:
            raise AssertionError(f"unexpected CLN call: {method}")
        queue = self.replies[method]
        reply = queue.pop(0) if len(queue) > 1 else queue[0]
        if callable(reply):
            reply = reply()
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
        self.real_send_to_bridge = cln_plugin.send_to_bridge
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
        cln_plugin.open_pays.clear()
        self.state_dir = tempfile.TemporaryDirectory()
        cln_plugin.settled_invoices.clear()
        cln_plugin.forwarded_htlcs.clear()
        cln_plugin.invoice_labels.clear()
        for name, value in (("NODE_ID", None), ("STATE_NODE_ID", None),
                            ("STATE_LSP_KEY", None),
                            ("_spawn", lambda target, *args: target(*args))):
            p = mock.patch.object(cln_plugin, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self.state_dir.cleanup)
        p = mock.patch.object(
            cln_plugin, "BRIDGE_STATE_FILE",
            os.path.join(self.state_dir.name, "bridge-plugin.state.json"))
        p.start()
        self.addCleanup(p.stop)
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

        self.clock = clock
        for name, repl in (("sleep", fake_sleep),
                           ("monotonic", lambda: clock["now"]),
                           ("time", lambda: clock["now"])):
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


class PayResultDeliveryTest(PluginTestCase):
    """A result is kept and repeated until the LSP acknowledges it, across
    link outages and plugin restarts."""

    def ack(self, request_id):
        cln_plugin.handle_bridge_msg({"method": "pay_result_ack",
                                      "request_id": request_id})

    def restart_plugin(self):
        """Forget everything in memory and read the state file, as a new
        process does before anything else."""
        cln_plugin.open_pays.clear()
        self.to_bridge.clear()
        cln_plugin.load_state()

    def run_inline(self):
        p = mock.patch.object(cln_plugin, "_spawn",
                              lambda target, *args: target(*args))
        p.start()
        self.addCleanup(p.stop)

    def test_result_is_repeated_until_acknowledged(self):
        self.use_cln(decode=decoded_invoice(4_000_000),
                     pay={"status": "complete", "payment_preimage": PREIMAGE})
        cln_plugin._do_pay(BOLT11, 7, PAYMENT_HASH, 4_000_000, 144)
        expected = {"method": "pay_result", "request_id": 7, "success": True,
                    "preimage": PREIMAGE}
        self.assertEqual(self.pay_results(), [expected])
        self.assertEqual(cln_plugin.resend_pay_results(), 1)
        self.assertEqual(cln_plugin.resend_pay_results(), 1)
        self.assertEqual(self.pay_results(), [expected] * 3)
        self.ack(7)
        self.assertEqual(cln_plugin.resend_pay_results(), 0)
        self.assertEqual(self.pay_results(), [expected] * 3)
        self.assertEqual(cln_plugin.open_pays, {})

    def test_result_reported_while_the_link_is_down_is_not_lost(self):
        self.use_cln(decode=decoded_invoice(4_000_000),
                     pay={"status": "complete", "payment_preimage": PREIMAGE})
        with mock.patch.object(cln_plugin, "send_to_bridge", lambda m: False):
            cln_plugin._do_pay(BOLT11, 7, PAYMENT_HASH, 4_000_000, 144)
        self.assertEqual(self.pay_results(), [])
        # The link comes back.
        cln_plugin.resend_pay_results()
        self.assertEqual(self.pay_results(), [{
            "method": "pay_result", "request_id": 7, "success": True,
            "preimage": PREIMAGE}])

    def test_refusals_are_repeated_until_acknowledged_too(self):
        self.use_cln(decode=decoded_invoice(4_000_000, payment_hash=OTHER_HASH))
        cln_plugin._do_pay(BOLT11, 8, PAYMENT_HASH, 4_000_000, 144)
        cln_plugin.resend_pay_results()
        self.assertEqual([m["success"] for m in self.pay_results()], [False, False])
        self.ack(8)
        self.assertEqual(cln_plugin.resend_pay_results(), 0)

    def test_undelivered_result_survives_a_restart(self):
        self.use_cln(decode=decoded_invoice(4_000_000),
                     pay={"status": "complete", "payment_preimage": PREIMAGE})
        with mock.patch.object(cln_plugin, "send_to_bridge", lambda m: False):
            cln_plugin._do_pay(BOLT11, 7, PAYMENT_HASH, 4_000_000, 144)
        self.restart_plugin()
        self.assertEqual(cln_plugin.recover_open_pays(), 1)
        cln_plugin.resend_pay_results()
        self.assertEqual(self.pay_results(), [{
            "method": "pay_result", "request_id": 7, "success": True,
            "preimage": PREIMAGE}])
        # Once acknowledged it is gone from disk as well.
        self.ack(7)
        self.restart_plugin()
        self.assertEqual(cln_plugin.recover_open_pays(), 0)

    def test_payment_in_flight_at_restart_is_followed_to_its_end(self):
        self.run_inline()
        # `pay` was running when the plugin died: nothing was reported.
        cln = self.use_cln(decode=decoded_invoice(4_000_000),
                           pay=KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):
            cln_plugin._do_pay(BOLT11, 7, PAYMENT_HASH, 4_000_000, 144)
        self.assertEqual(self.pay_results(), [])
        self.restart_plugin()

        cln = self.use_cln(listpays=[listed("pending"), listed("pending"),
                                     listed("complete")])
        self.assertEqual(cln_plugin.recover_open_pays(), 1)
        self.assertEqual(cln.calls_to("pay"), [])       # never paid again
        self.assertEqual(len(cln.calls_to("listpays")), 3)
        self.assertEqual(self.pay_results(), [{
            "method": "pay_result", "request_id": 7, "success": True,
            "preimage": PREIMAGE}])

    def test_payment_that_failed_while_the_plugin_was_down(self):
        self.run_inline()
        self.use_cln(decode=decoded_invoice(4_000_000), pay=KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):
            cln_plugin._do_pay(BOLT11, 7, PAYMENT_HASH, 4_000_000, 144)
        self.restart_plugin()
        # Long after the request: no attempt can still start.
        self.clock["now"] += 3600
        self.use_cln(listpays=listed("failed"))
        cln_plugin.recover_open_pays()
        self.assertEqual(self.sleeps, [])
        self.assert_pay_failed(7)

    def test_restart_right_after_the_request_waits_out_the_retry_window(self):
        self.run_inline()
        self.use_cln(decode=decoded_invoice(4_000_000), pay=KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):
            cln_plugin._do_pay(BOLT11, 7, PAYMENT_HASH, 4_000_000, 144)
        self.restart_plugin()
        # CLN's pay may still be between attempts: "none yet" is not final.
        self.use_cln(listpays=listed())
        cln_plugin.recover_open_pays()
        window = cln_plugin.PAY_RETRY_FOR + cln_plugin.PAY_SETTLE_GRACE
        self.assertGreaterEqual(sum(self.sleeps), window)
        self.assert_pay_failed(7)

    def test_repeated_request_is_not_paid_twice(self):
        cln = self.use_cln(decode=decoded_invoice(4_000_000),
                           pay={"status": "complete", "payment_preimage": PREIMAGE})
        cln_plugin._do_pay(BOLT11, 7, PAYMENT_HASH, 4_000_000, 144)
        cln_plugin._do_pay(BOLT11, 7, PAYMENT_HASH, 4_000_000, 144)
        self.assertEqual(len(cln.calls_to("pay")), 1)
        # The known result goes out again instead.
        self.assertEqual([m["success"] for m in self.pay_results()], [True, True])

    def test_invoice_payable_to_this_node_is_not_paid(self):
        cln = self.use_cln(decode=decoded_invoice(4_000_000, payee=OWN_NODE.upper()),
                           pay={"status": "complete", "payment_preimage": PREIMAGE})
        cln_plugin._do_pay(BOLT11, 7, PAYMENT_HASH, 4_000_000, 144)
        self.assertEqual(cln.calls_to("pay"), [])
        self.assert_pay_failed(7)

    def test_invoice_of_a_factory_client_is_not_paid_outside(self):
        for where in (cln_plugin.registered_invoices, cln_plugin.settled_invoices):
            self.to_bridge.clear()
            cln_plugin.open_pays.clear()
            cln_plugin.registered_invoices.clear()
            cln_plugin.settled_invoices.clear()
            if isinstance(where, set):
                where.add(PAYMENT_HASH)
            else:
                where[PAYMENT_HASH] = {"preimage": PREIMAGE, "upstream": ""}
            cln = self.use_cln(
                decode=decoded_invoice(4_000_000, payee="03" + "ee" * 32),
                pay={"status": "complete", "payment_preimage": PREIMAGE})
            cln_plugin._do_pay(BOLT11, 7, PAYMENT_HASH, 4_000_000, 144)
            self.assertEqual(cln.calls_to("pay"), [])
            self.assert_pay_failed(7)

    def test_other_payees_are_paid_even_if_the_node_id_is_unknown(self):
        cln = self.use_cln(decode=decoded_invoice(4_000_000, payee="03" + "ee" * 32),
                           pay={"status": "complete", "payment_preimage": PREIMAGE},
                           getinfo=cln_plugin.ClnRpcError("Connection refused"))
        cln_plugin._do_pay(BOLT11, 7, PAYMENT_HASH, 4_000_000, 144)
        self.assertEqual(len(cln.calls_to("pay")), 1)

    def test_second_request_for_a_hash_being_paid_is_refused(self):
        self.use_cln(decode=decoded_invoice(4_000_000),
                     pay={"status": "complete", "payment_preimage": PREIMAGE})
        cln_plugin._do_pay(BOLT11, 7, PAYMENT_HASH, 4_000_000, 144)
        cln = self.use_cln(decode=decoded_invoice(4_000_000),
                           pay={"status": "complete", "payment_preimage": PREIMAGE})
        cln_plugin._do_pay(BOLT11, 8, PAYMENT_HASH, 4_000_000, 144)
        self.assertEqual(cln.calls_to("pay"), [])
        self.assertEqual(self.pay_results()[-1], {
            "method": "pay_result", "request_id": 8, "success": False,
            "preimage": "00" * 32})

    def test_invoice_the_node_already_paid_is_not_charged_again(self):
        # No record of our own (state lost), but CLN has paid this hash.
        for status in ("complete", "pending"):
            self.to_bridge.clear()
            cln_plugin.open_pays.clear()
            cln = self.use_cln(
                decode=decoded_invoice(4_000_000),
                pay={"status": "complete", "payment_preimage": PREIMAGE},
                listsendpays={"payments": [{"payment_hash": PAYMENT_HASH,
                                            "status": status}]})
            cln_plugin._do_pay(BOLT11, 9, PAYMENT_HASH, 4_000_000, 144)
            self.assertEqual(cln.calls_to("listsendpays"),
                             [{"payment_hash": PAYMENT_HASH}])
            self.assertEqual(cln.calls_to("pay"), [], status)
            self.assert_pay_failed(9)

    def test_earlier_failed_attempts_do_not_block_a_new_payment(self):
        cln = self.use_cln(
            decode=decoded_invoice(4_000_000),
            pay={"status": "complete", "payment_preimage": PREIMAGE},
            listsendpays={"payments": [{"payment_hash": PAYMENT_HASH,
                                        "status": "failed"}]})
        cln_plugin._do_pay(BOLT11, 9, PAYMENT_HASH, 4_000_000, 144)
        self.assertEqual(len(cln.calls_to("pay")), 1)

    def test_no_payment_when_earlier_payments_cannot_be_checked(self):
        cln = self.use_cln(
            decode=decoded_invoice(4_000_000),
            pay={"status": "complete", "payment_preimage": PREIMAGE},
            listsendpays=cln_plugin.ClnRpcError("Connection refused"))
        cln_plugin._do_pay(BOLT11, 9, PAYMENT_HASH, 4_000_000, 144)
        self.assertEqual(cln.calls_to("pay"), [])
        self.assert_pay_failed(9)

    def test_ack_for_a_payment_still_in_flight_does_not_drop_it(self):
        cln_plugin._open_pay(7, PAYMENT_HASH)
        self.ack(7)
        self.assertIn(7, cln_plugin.open_pays)
        # Its record is still on disk for a restart to pick up.
        self.restart_plugin()
        self.assertIn(7, cln_plugin.open_pays)

    def test_rejected_result_is_kept_but_not_repeated(self):
        logged = []
        self.use_cln(decode=decoded_invoice(4_000_000),
                     pay={"status": "complete", "payment_preimage": PREIMAGE})
        cln_plugin._do_pay(BOLT11, 7, PAYMENT_HASH, 4_000_000, 144)
        with mock.patch.object(cln_plugin, "log", logged.append):
            for _ in range(2):
                cln_plugin.handle_bridge_msg({
                    "method": "pay_result_ack", "request_id": 7,
                    "status": "rejected", "reason": "preimage_mismatch"})
        # Said once, loudly, with the reason.
        self.assertEqual(len(logged), 1)
        self.assertIn("REJECTED", logged[0])
        self.assertIn("preimage_mismatch", logged[0])
        # Not sent again, but not forgotten either, also after a restart.
        self.assertEqual(cln_plugin.resend_pay_results(), 0)
        self.assertEqual(len(self.pay_results()), 1)
        self.restart_plugin()
        self.assertEqual(cln_plugin.open_pays[7]["rejected"], "preimage_mismatch")
        self.assertEqual(cln_plugin.resend_pay_results(), 0)

    def test_no_invoice_is_created_for_a_hash_being_paid(self):
        started = []

        class RecordingThread:
            def __init__(self, target, args=(), daemon=None):
                started.append(args)

            def start(self):
                pass

        self.use_cln(decode=decoded_invoice(4_000_000), pay=PAY_TIMEOUT,
                     listpays=listed("complete"))
        cln_plugin._do_pay(BOLT11, 7, PAYMENT_HASH, 4_000_000, 144)
        self.to_bridge.clear()
        register = {"method": "invoice_registered", "payment_hash": PAYMENT_HASH,
                    "preimage": PREIMAGE, "amount_msat": 4_000_000,
                    "dest_client": 0}
        with mock.patch.object(cln_plugin.threading, "Thread", RecordingThread):
            cln_plugin.handle_bridge_msg(register)
            self.assertEqual(started, [])
            self.assertEqual(self.to_bridge, [{
                "method": "invoice_bolt11", "payment_hash": PAYMENT_HASH,
                "bolt11": ""}])
            # Another hash gets its invoice as before.
            cln_plugin.handle_bridge_msg(dict(register, payment_hash=OTHER_HASH))
            self.assertEqual(len(started), 1)

    def test_failure_is_not_reported_before_the_retry_window_from_launch(self):
        # The request sat for a long time before `pay` was launched (slow
        # decode).  `pay` then hangs and its attempt shows as failed: CLN
        # may still retry until its window, counted from the launch, is over.
        def slow_decode():
            self.clock["now"] += 500
            return decoded_invoice(4_000_000)

        self.use_cln(decode=slow_decode, pay=PAY_TIMEOUT, listpays=listed("failed"))
        cln_plugin._do_pay(BOLT11, 7, PAYMENT_HASH, 4_000_000, 144)
        window = cln_plugin.PAY_RETRY_FOR + cln_plugin.PAY_SETTLE_GRACE
        self.assertGreaterEqual(sum(self.sleeps), window)
        self.assert_pay_failed(7)

    def test_launch_time_is_what_a_restart_counts_from(self):
        self.run_inline()
        self.use_cln(decode=decoded_invoice(4_000_000), pay=KeyboardInterrupt())
        requested = self.clock["now"]
        with self.assertRaises(KeyboardInterrupt):
            cln_plugin._do_pay(BOLT11, 7, PAYMENT_HASH, 4_000_000, 144)
        rec = cln_plugin.open_pays[7]
        self.assertTrue(rec["launched"])
        self.assertEqual(rec["started"], requested)
        # A request that never got as far as `pay` has no launch time: after
        # a restart its window is counted from then, not from zero.
        cln_plugin._open_pay(8, OTHER_HASH)
        self.assertFalse(cln_plugin.open_pays[8]["launched"])
        self.assertIsNone(cln_plugin.open_pays[8]["started"])
        self.restart_plugin()
        self.use_cln(listpays=listed())
        cln_plugin.recover_open_pays()
        window = cln_plugin.PAY_RETRY_FOR + cln_plugin.PAY_SETTLE_GRACE
        self.assertGreaterEqual(sum(self.sleeps), window)
        self.assertEqual(sorted(m["request_id"] for m in self.pay_results()), [7, 8])


class StateFileTest(PluginTestCase):
    """The state file is written whole, belongs to one node and one LSP, and
    is never silently ignored."""

    NODE = OWN_NODE

    def path(self):
        return cln_plugin.BRIDGE_STATE_FILE

    def some_state(self):
        cln_plugin._open_pay(7, PAYMENT_HASH)
        cln_plugin._mark_settled(PAYMENT_HASH2, PREIMAGE2, "100x1x0:5")
        cln_plugin._note_forwarded("100x1x0:6", OTHER_HASH, True)

    def forget(self):
        cln_plugin.open_pays.clear()
        cln_plugin.settled_invoices.clear()
        cln_plugin.forwarded_htlcs.clear()

    def test_everything_survives_a_reload(self):
        self.some_state()
        self.forget()
        self.assertEqual(cln_plugin.load_state(), 1)
        self.assertEqual(cln_plugin.open_pays[7]["payment_hash"], PAYMENT_HASH)
        self.assertEqual(cln_plugin.settled_invoices[PAYMENT_HASH2],
                         {"preimage": PREIMAGE2, "upstream": "100x1x0:5"})
        self.assertEqual(cln_plugin.forwarded_htlcs["100x1x0:6"],
                         {"payment_hash": OTHER_HASH, "factory_invoice": True})

    def test_file_is_private_and_no_temporary_files_are_left(self):
        self.some_state()
        self.assertEqual(os.stat(self.path()).st_mode & 0o777, 0o600)
        self.assertEqual(os.listdir(os.path.dirname(self.path())),
                         [os.path.basename(self.path())])

    def test_concurrent_saves_leave_one_complete_state(self):
        import threading as real_threading
        self.some_state()
        errors = []

        def hammer(n):
            try:
                for i in range(5):
                    cln_plugin._note_forwarded(f"{n}x{i}x0:1", OTHER_HASH, False)
            except Exception as e:      # pragma: no cover
                errors.append(e)

        threads = [real_threading.Thread(target=hammer, args=(n,)) for n in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        with open(self.path()) as f:
            state = json.load(f)
        self.assertEqual(len(state["forwarded"]), 6 * 5 + 1)
        self.assertEqual(os.listdir(os.path.dirname(self.path())),
                         [os.path.basename(self.path())])

    def test_a_missing_file_is_a_fresh_start(self):
        self.assertEqual(cln_plugin.load_state(self.NODE), 0)
        self.assertEqual(cln_plugin.STATE_NODE_ID, self.NODE)

    def test_a_damaged_file_is_an_error_not_an_empty_state(self):
        for text in ("{ not json", "", "[1, 2]", '{"pays": []}',
                     '{"pays": {"x": {}}}', '{"pays": {"7": 5}}',
                     '{"settled": "no"}'):
            with open(self.path(), "w") as f:
                f.write(text)
            self.forget()
            with self.assertRaises(cln_plugin.StateFileError, msg=text):
                cln_plugin.load_state(self.NODE)
            self.assertEqual(cln_plugin.open_pays, {})

    def test_an_unreadable_file_is_an_error(self):
        os.mkdir(self.path())       # a directory where the file should be
        with self.assertRaises(cln_plugin.StateFileError):
            cln_plugin.load_state(self.NODE)

    def test_a_file_from_another_node_is_refused(self):
        cln_plugin.STATE_NODE_ID = "03" + "aa" * 32
        self.some_state()
        self.forget()
        with self.assertRaises(cln_plugin.StateFileError) as caught:
            cln_plugin.load_state(self.NODE)
        self.assertIn("belongs to node", str(caught.exception))
        self.assertEqual(cln_plugin.open_pays, {})
        # The node it was written for reads it.
        self.assertEqual(cln_plugin.load_state("03" + "aa" * 32), 1)

    def test_the_node_id_is_recorded_with_the_state(self):
        self.use_cln()
        cln_plugin.init_state()
        self.some_state()
        with open(self.path()) as f:
            self.assertEqual(json.load(f)["node_id"], OWN_NODE)

    def test_plugin_stops_on_a_damaged_file(self):
        logged = []
        with open(self.path(), "w") as f:
            f.write("{ not json")
        self.use_cln()
        with mock.patch.object(cln_plugin, "log", logged.append), \
                mock.patch.object(cln_plugin.sys, "stderr"), \
                self.assertRaises(SystemExit) as stopped:
            cln_plugin.init_state()
        self.assertNotEqual(stopped.exception.code, 0)
        self.assertEqual(len(logged), 1)
        self.assertIn("FATAL", logged[0])
        self.assertIn("not valid JSON", logged[0])
        # The damaged file is left as it was, for the operator.
        with open(self.path()) as f:
            self.assertEqual(f.read(), "{ not json")

    def test_plugin_stops_when_the_node_cannot_be_identified(self):
        self.use_cln(getinfo=cln_plugin.ClnRpcError("Connection refused"))
        with mock.patch.object(cln_plugin.sys, "stderr"), \
                self.assertRaises(SystemExit):
            cln_plugin.init_state(attempts=3)
        self.assertEqual(self.sleeps, [1, 1, 1])

    def test_state_is_tied_to_the_lsp_the_bridge_serves(self):
        lsp_a, lsp_b = "02" + "a1" * 32, "02" + "b2" * 32
        self.assertTrue(cln_plugin.check_lsp_identity(lsp_a))
        self.assertTrue(cln_plugin.check_lsp_identity(lsp_a))
        self.assertFalse(cln_plugin.check_lsp_identity(lsp_b))
        self.assertFalse(cln_plugin.check_lsp_identity(""))
        # It is part of the state on disk.
        cln_plugin.STATE_LSP_KEY = None
        cln_plugin.load_state()
        self.assertEqual(cln_plugin.STATE_LSP_KEY, lsp_a)
        self.assertFalse(cln_plugin.check_lsp_identity(lsp_b))


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

    # --- a fulfilled invoice stays closed ---

    def fulfil(self, rpc_id):
        self.register()
        cln_plugin.handle_htlc_accepted(rpc_id, htlc())
        cln_plugin.handle_bridge_msg({
            "method": "htlc_resolve", "payment_hash": PAYMENT_HASH,
            "htlc_id": 1, "result": "fulfill", "preimage": PREIMAGE})

    def test_later_htlc_for_a_fulfilled_invoice_is_failed_not_continued(self):
        self.fulfil(40)
        # CLN still has the invoice; the registry no longer does.
        self.assertNotIn(PAYMENT_HASH, cln_plugin.registered_invoices)
        cln_plugin.handle_htlc_accepted(41, htlc())
        cln_plugin.handle_htlc_accepted(42, htlc(short_channel_id="1x1x1"))
        self.assertEqual(self.hook_answers()[1:], [(41, fail()), (42, fail())])
        self.assertEqual(len(self.to_lsp()), 1)

    def test_fulfilled_invoice_stays_closed_across_a_restart(self):
        self.fulfil(43)
        cln_plugin.settled_invoices.clear()
        cln_plugin.registered_invoices.clear()
        cln_plugin.load_state()
        # CLN lists the invoice as unpaid: it is not taken back in...
        self.use_cln(listinvoices={"invoices": [
            {"label": "superscalar-aa-1", "status": "unpaid",
             "payment_hash": PAYMENT_HASH}]})
        cln_plugin.recover_registered_invoices()
        self.assertEqual(cln_plugin.registered_invoices, set())
        # ...and an HTLC for it is failed.
        cln_plugin.handle_htlc_accepted(44, htlc())
        self.assertEqual(self.hook_answers()[-1], (44, fail()))

    def test_cln_copy_of_a_fulfilled_invoice_is_deleted(self):
        cln = self.use_cln(delinvoice={})
        cln_plugin.invoice_labels[PAYMENT_HASH] = "superscalar-aa-1"
        self.fulfil(45)
        self.assertEqual(cln.calls_to("delinvoice"),
                         [{"label": "superscalar-aa-1", "status": "unpaid"}])
        # A failed delete changes nothing else: the hash stays closed.
        cln_plugin.settled_invoices.clear()
        cln_plugin.invoice_labels[PAYMENT_HASH2] = "superscalar-bb-2"
        self.use_cln(delinvoice=cln_plugin.ClnRpcError("no such invoice"))
        cln_plugin.registered_invoices.add(PAYMENT_HASH2)
        cln_plugin.handle_htlc_accepted(46, htlc(payment_hash=PAYMENT_HASH2))
        cln_plugin.handle_bridge_msg({
            "method": "htlc_resolve", "payment_hash": PAYMENT_HASH2,
            "htlc_id": 2, "result": "fulfill", "preimage": PREIMAGE2})
        self.assertIn(PAYMENT_HASH2, cln_plugin.settled_invoices)

    def test_fulfilled_forward_is_not_remembered_as_an_invoice(self):
        cln_plugin.handle_htlc_accepted(47, htlc(short_channel_id="1x1x1"))
        cln_plugin.handle_bridge_msg({
            "method": "htlc_resolve", "payment_hash": PAYMENT_HASH,
            "htlc_id": 1, "result": "fulfill", "preimage": PREIMAGE})
        self.assertEqual(cln_plugin.settled_invoices, {})

    def test_settled_memory_is_bounded(self):
        with mock.patch.object(cln_plugin, "SETTLED_MAX", 3), \
                mock.patch.object(cln_plugin, "save_state", lambda: True):
            for i in range(5):
                cln_plugin._mark_settled(f"{i:064x}", "00" * 32, "")
        self.assertEqual(list(cln_plugin.settled_invoices),
                         [f"{i:064x}" for i in (2, 3, 4)])

    # --- CLN restarts and offers unresolved HTLCs again ---

    def cln_restart(self):
        """What a restart of CLN and the plugin leaves: the state file."""
        cln_plugin.pending_htlcs.clear()
        cln_plugin.registered_invoices.clear()
        cln_plugin.settled_invoices.clear()
        cln_plugin.forwarded_htlcs.clear()
        self.to_bridge.clear()
        self.to_cln.clear()
        cln_plugin.load_state()

    def forward_then_restart(self):
        self.register()
        cln_plugin.handle_htlc_accepted(60, htlc(channel="100x1x0", htlc_id=5))
        self.assertEqual(len(self.to_lsp()), 1)
        self.cln_restart()

    def test_replayed_htlc_is_held_and_offered_to_the_lsp_again(self):
        self.forward_then_restart()
        # The invoice is no longer listed as unpaid (it expired, say), so
        # the registry does not know the hash.
        self.assertEqual(cln_plugin.registered_invoices, set())
        cln_plugin.handle_htlc_accepted(61, htlc(channel="100x1x0", htlc_id=5))
        self.assertEqual(self.hook_answers(), [])
        self.assertEqual([m["upstream_id"] for m in self.to_lsp()], ["100x1x0:5"])
        self.assertTrue(cln_plugin.pending_htlcs[PAYMENT_HASH]["factory_invoice"])
        # The LSP's verdict resolves it as usual.
        cln_plugin.handle_bridge_msg({
            "method": "htlc_resolve", "payment_hash": PAYMENT_HASH,
            "htlc_id": 1, "result": "fulfill", "preimage": PREIMAGE})
        self.assertEqual(self.hook_answers(), [
            (61, {"result": "resolve", "payment_key": PREIMAGE})])

    def test_replayed_htlc_is_held_while_the_bridge_is_unreachable(self):
        self.forward_then_restart()
        with mock.patch.object(cln_plugin, "send_to_bridge", lambda m: False):
            cln_plugin.handle_htlc_accepted(62, htlc(channel="100x1x0", htlc_id=5))
        # Neither failed nor passed to CLN.
        self.assertEqual(self.hook_answers(), [])
        self.assertEqual(cln_plugin.pending_htlcs[PAYMENT_HASH]["rpc_id"], 62)
        # When the bridge is back it is offered to the LSP.
        self.assertEqual(cln_plugin.reannounce_held_htlcs(), 1)
        self.assertEqual([m["upstream_id"] for m in self.to_lsp()], ["100x1x0:5"])

    def test_replayed_htlc_is_held_while_invoices_cannot_be_listed(self):
        self.forward_then_restart()
        cln_plugin.registry_recovered = False
        cln = self.use_cln(listinvoices=cln_plugin.ClnRpcError("Connection refused"))
        cln_plugin.handle_htlc_accepted(63, htlc(channel="100x1x0", htlc_id=5))
        self.assertEqual(self.hook_answers(), [])
        self.assertEqual(len(self.to_lsp()), 1)
        # A different HTLC cannot be classified and is failed, as before.
        cln_plugin.handle_htlc_accepted(64, htlc(payment_hash=OTHER_HASH,
                                                 channel="100x1x0", htlc_id=9))
        self.assertEqual(self.hook_answers(), [(64, fail())])

    def test_replay_of_the_htlc_that_paid_gets_the_same_answer(self):
        self.register()
        cln_plugin.handle_htlc_accepted(65, htlc(channel="100x1x0", htlc_id=5))
        cln_plugin.handle_bridge_msg({
            "method": "htlc_resolve", "payment_hash": PAYMENT_HASH,
            "htlc_id": 1, "result": "fulfill", "preimage": PREIMAGE})
        # CLN went down before it processed that answer.
        self.cln_restart()
        cln_plugin.handle_htlc_accepted(66, htlc(channel="100x1x0", htlc_id=5))
        self.assertEqual(self.hook_answers(), [
            (66, {"result": "resolve", "payment_key": PREIMAGE})])
        self.assertEqual(self.to_lsp(), [])
        self.assertEqual(self.resolved_acks(), [
            {"method": "htlc_resolved", "payment_hash": PAYMENT_HASH}])
        # Any other HTLC for the fulfilled hash is still failed.
        cln_plugin.handle_htlc_accepted(67, htlc(channel="100x1x0", htlc_id=6))
        cln_plugin.handle_htlc_accepted(68, htlc())
        self.assertEqual(self.hook_answers()[1:], [(67, fail()), (68, fail())])

    def test_answered_htlcs_are_no_longer_held_for_after_a_restart(self):
        self.register()
        self.register(PAYMENT_HASH2)
        cln_plugin.handle_htlc_accepted(69, htlc(channel="100x1x0", htlc_id=5))
        cln_plugin.handle_htlc_accepted(70, htlc(payment_hash=PAYMENT_HASH2,
                                                 channel="100x1x0", htlc_id=6))
        self.assertEqual(set(cln_plugin.forwarded_htlcs), {"100x1x0:5", "100x1x0:6"})
        self.lsp_fails("insufficient_funds")
        cln_plugin.handle_bridge_msg({
            "method": "htlc_resolve", "payment_hash": PAYMENT_HASH2,
            "htlc_id": 2, "result": "fulfill", "preimage": PREIMAGE2})
        self.cln_restart()
        self.assertEqual(cln_plugin.forwarded_htlcs, {})
        # A failed HTLC offered again is a new HTLC (the invoice is unknown
        # after the restart here, so it is CLN's).
        cln_plugin.handle_htlc_accepted(71, htlc(channel="100x1x0", htlc_id=5))
        self.assertEqual(self.hook_answers(), [(71, CONTINUE)])

    def test_htlc_never_sent_is_not_held_after_a_restart(self):
        self.register()
        with mock.patch.object(cln_plugin, "send_to_bridge", lambda m: False):
            cln_plugin.handle_htlc_accepted(72, htlc(channel="100x1x0", htlc_id=5))
        self.assertEqual(self.hook_answers(), [(72, fail())])
        self.assertEqual(cln_plugin.forwarded_htlcs, {})

    def test_fulfil_with_a_wrong_preimage_does_not_resolve_the_htlc(self):
        self.register()
        cln_plugin.handle_htlc_accepted(73, htlc(channel="100x1x0", htlc_id=5))
        for bad in ("22" * 32, "", "zz", None):
            cln_plugin.handle_bridge_msg({
                "method": "htlc_resolve", "payment_hash": PAYMENT_HASH,
                "htlc_id": 1, "result": "fulfill", "preimage": bad})
        # Not answered, still held, still ours to resolve.
        self.assertEqual(self.hook_answers(), [])
        self.assertEqual(cln_plugin.pending_htlcs[PAYMENT_HASH]["rpc_id"], 73)
        self.assertNotIn(PAYMENT_HASH, cln_plugin.settled_invoices)
        self.assertEqual(self.resolved_acks(), [])
        cln_plugin.handle_bridge_msg({
            "method": "htlc_resolve", "payment_hash": PAYMENT_HASH,
            "htlc_id": 1, "result": "fulfill", "preimage": PREIMAGE})
        self.assertEqual(self.hook_answers(), [
            (73, {"result": "resolve", "payment_key": PREIMAGE})])

    def test_factory_invoice_outlives_the_hold_time_of_its_htlc(self):
        completed = subprocess.CompletedProcess([], 0, '{"bolt11": "lnbcrt1"}', "")
        with mock.patch.object(cln_plugin.subprocess, "run",
                               return_value=completed) as run:
            cln_plugin._create_cln_invoice(PAYMENT_HASH, PREIMAGE, 5_000_000)
        argv = run.call_args[0][0]
        expiry = [int(a.split("=")[1]) for a in argv if a.startswith("expiry=")]
        hold = cln_plugin.FACTORY_INVOICE_CLTV * 600
        self.assertEqual(len(expiry), 1)
        self.assertGreaterEqual(expiry[0], 3600 + hold)
        self.assertIn(f"cltv={cln_plugin.FACTORY_INVOICE_CLTV}", argv)

    # --- telling the LSP, and telling it again ---

    def resolved_acks(self):
        return [m for m in self.to_bridge if m.get("method") == "htlc_resolved"]

    def test_fulfil_is_confirmed_to_the_lsp(self):
        self.fulfil(50)
        self.assertEqual(self.resolved_acks(), [
            {"method": "htlc_resolved", "payment_hash": PAYMENT_HASH}])
        # The LSP repeats the fulfil (our confirmation was lost): confirmed
        # again, CLN is not answered twice.
        cln_plugin.handle_bridge_msg({
            "method": "htlc_resolve", "payment_hash": PAYMENT_HASH,
            "htlc_id": 1, "result": "fulfill", "preimage": PREIMAGE})
        self.assertEqual(len(self.resolved_acks()), 2)
        self.assertEqual(len(self.hook_answers()), 1)

    def test_fulfil_for_an_unknown_htlc_is_not_confirmed(self):
        cln_plugin.handle_bridge_msg({
            "method": "htlc_resolve", "payment_hash": PAYMENT_HASH2,
            "htlc_id": 1, "result": "fulfill", "preimage": PREIMAGE2})
        self.assertEqual(self.resolved_acks(), [])
        self.assertEqual(self.hook_answers(), [])

    def test_failure_is_not_confirmed_as_a_fulfil(self):
        self.register()
        cln_plugin.handle_htlc_accepted(51, htlc())
        self.lsp_fails("insufficient_funds")
        self.assertEqual(self.resolved_acks(), [])

    def test_held_htlcs_are_offered_again_after_a_reconnect(self):
        self.register()
        self.register(OTHER_HASH)
        cln_plugin.handle_htlc_accepted(52, htlc(channel="100x1x0", htlc_id=5))
        cln_plugin.handle_htlc_accepted(53, htlc(payment_hash=OTHER_HASH))  # unnamed
        first = self.to_lsp()[0]
        self.to_bridge.clear()
        self.assertEqual(cln_plugin.reannounce_held_htlcs(), 1)
        # The named one goes out again exactly as before; the unnamed one,
        # which the LSP could only refuse, does not.
        self.assertEqual(self.to_lsp(), [first])
        self.assertEqual(self.hook_answers(), [])
        # Resolved HTLCs are not offered again.
        cln_plugin.handle_bridge_msg({
            "method": "htlc_resolve", "payment_hash": PAYMENT_HASH,
            "htlc_id": 1, "result": "fulfill", "preimage": PREIMAGE})
        self.to_bridge.clear()
        self.assertEqual(cln_plugin.reannounce_held_htlcs(), 0)

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


class FakeBridge:
    """The bridge's end of a new connection, as a socket for the plugin.
    `secret` is what this peer holds (None: it holds none and bluffs)."""

    def __init__(self, secret, instead_of_challenge=None, accept=True,
                 lsp_pubkey="", ok_mac="good"):
        self.lsp_pubkey = lsp_pubkey
        self.ok_mac = ok_mac    # how auth_ok is authenticated: good/none/bad
        self.secret = secret
        self.instead_of_challenge = instead_of_challenge
        self.accept = accept
        self.sent = []            # decoded lines the plugin sent
        self.raw = b""
        self.inbox = b""
        self.nonce = bytes(range(32))
        self.closed = False
        self.timeout = "unset"

    def settimeout(self, t):
        self.timeout = t

    def close(self):
        self.closed = True

    def recv(self, n):
        out, self.inbox = self.inbox[:n], self.inbox[n:]
        return out

    def _reply(self, obj):
        self.inbox += (json.dumps(obj) + "\n").encode()

    def sendall(self, data):
        self.raw += data
        for line in data.split(b"\n"):
            if not line:
                continue
            if not line.startswith(b"{"):       # a session line: "<mac> <json>"
                line = line.split(b" ", 1)[1]
            msg = json.loads(line)
            self.sent.append(msg)
            if msg["method"] == "auth_hello":
                self.plugin_nonce = bytes.fromhex(msg["nonce"])
                if self.instead_of_challenge is not None:
                    self._reply(self.instead_of_challenge)
                    continue
                key = self.secret or "00" * 32
                self._reply({
                    "method": "auth_challenge", "nonce": self.nonce.hex(),
                    "proof": cln_plugin.auth_proof(
                        key, b"bridge", self.plugin_nonce, self.nonce)})
            elif msg["method"] == "auth_response" and self.accept:
                line = json.dumps({"method": "auth_ok",
                                   "lsp_pubkey": self.lsp_pubkey}).encode()
                self.key = cln_plugin.session_key(
                    self.secret or "00" * 32, self.plugin_nonce, self.nonce)
                mac = cln_plugin.line_mac(self.key, b"b2p", 0, line).encode()
                if self.ok_mac == "bad":
                    mac = cln_plugin.line_mac(b"k" * 32, b"b2p", 0, line).encode()
                if self.ok_mac == "none":
                    self.inbox += line + b"\n"
                else:
                    self.inbox += mac + b" " + line + b"\n"


class BridgeAuthTest(PluginTestCase):
    """Neither side sends the secret; the plugin answers, and listens to,
    only a peer that has proven it holds it."""

    SECRET = "5c" * 32

    def setUp(self):
        super().setUp()
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.secret_path = os.path.join(self.dir.name, "bridge-plugin.secret")
        for name, value in (("BRIDGE_SECRET_FILE", self.secret_path),
                            ("bridge_sock", None), ("bridge_session", None)):
            p = mock.patch.object(cln_plugin, name, value)
            p.start()
            self.addCleanup(p.stop)

    def write_secret(self, text, mode=0o600):
        with open(self.secret_path, "w") as f:
            f.write(text)
        os.chmod(self.secret_path, mode)

    def connect(self, bridge):
        with mock.patch.object(cln_plugin.socket, "create_connection",
                               return_value=bridge) as create:
            ok = cln_plugin.connect_bridge()
        return ok, create

    def test_handshake_with_the_real_bridge(self):
        self.write_secret(self.SECRET + "\n")
        bridge = FakeBridge(self.SECRET)
        ok, create = self.connect(bridge)
        self.assertTrue(ok)
        create.assert_called_once()
        self.assertEqual([m["method"] for m in bridge.sent],
                         ["auth_hello", "auth_response"])
        self.assertEqual(bridge.sent[1]["proof"], cln_plugin.auth_proof(
            self.SECRET, b"plugin", bridge.plugin_nonce, bridge.nonce))
        self.assertIs(cln_plugin.bridge_sock, bridge)
        self.assertIsNone(bridge.timeout)       # blocking reads from here on
        self.assertEqual(bridge.inbox, b"")     # nothing swallowed

    def test_proofs_match_the_bridge_implementation(self):
        # The same fixed values are asserted in the bridge's C tests.
        secret = "00112233445566778899aabbccddeeff" * 2
        np, nb = b"" * 32, b"" * 32
        self.assertEqual(
            cln_plugin.auth_proof(secret, b"plugin", np, nb),
            "7f0ce9d7bbc1eb564d7696fb9dc9cd3d8ba0f4c0ef0da075860610dcc7ad929e")
        self.assertEqual(
            cln_plugin.auth_proof(secret, b"bridge", np, nb),
            "3b505ab3809df5713d5f24a15bda1465e41680ccf6ec56a5763c789ed46f5aa1")

    def test_the_secret_is_never_sent(self):
        self.write_secret(self.SECRET)
        for bridge in (FakeBridge(self.SECRET), FakeBridge(None),
                       FakeBridge("ab" * 32)):
            self.connect(bridge)
            self.assertNotIn(self.SECRET.encode(), bridge.raw.lower())
            self.assertNotIn(bytes.fromhex(self.SECRET), bridge.raw)

    def test_a_fresh_nonce_every_time(self):
        self.write_secret(self.SECRET)
        first, second = FakeBridge(self.SECRET), FakeBridge(self.SECRET)
        self.connect(first)
        self.connect(second)
        self.assertNotEqual(first.sent[0]["nonce"], second.sent[0]["nonce"])
        self.assertEqual(len(bytes.fromhex(first.sent[0]["nonce"])), 32)

    def test_peer_without_the_secret_gets_no_proof_and_no_link(self):
        self.write_secret(self.SECRET)
        # Something else listening on the bridge's port.
        for impostor in (FakeBridge(None), FakeBridge("ab" * 32)):
            ok, _ = self.connect(impostor)
            self.assertFalse(ok)
            # It saw our nonce and nothing derived from the secret.
            self.assertEqual([m["method"] for m in impostor.sent], ["auth_hello"])
            self.assertIsNone(cln_plugin.bridge_sock)
            self.assertTrue(impostor.closed)

    def test_messages_from_an_unproven_peer_are_not_acted_on(self):
        self.write_secret(self.SECRET)
        handled = []
        pay = {"method": "pay_request", "bolt11": BOLT11, "request_id": 1,
               "payment_hash": PAYMENT_HASH, "max_total_msat": 10 ** 9,
               "max_delay": 100}
        for first_reply in (pay, {"method": "auth_ok"},
                            {"method": "auth_challenge", "nonce": "zz",
                             "proof": "00" * 32},
                            {"method": "auth_challenge",
                             "nonce": "11" * 32}, [1, 2], "text"):
            impostor = FakeBridge(None, instead_of_challenge=first_reply)
            with mock.patch.object(cln_plugin, "handle_bridge_msg",
                                   handled.append):
                ok, _ = self.connect(impostor)
            self.assertFalse(ok, first_reply)
            self.assertEqual(len(impostor.sent), 1)
            self.assertIsNone(cln_plugin.bridge_sock)
        self.assertEqual(handled, [])

    def test_reflected_plugin_proof_is_not_a_bridge_proof(self):
        self.write_secret(self.SECRET)

        class Reflector(FakeBridge):
            def sendall(self, data):
                msg = json.loads(data)
                self.sent.append(msg)
                if msg["method"] == "auth_hello":
                    nonce = bytes.fromhex(msg["nonce"])
                    # the proof the *plugin* would give for these nonces
                    self._reply({
                        "method": "auth_challenge", "nonce": self.nonce.hex(),
                        "proof": cln_plugin.auth_proof(
                            BridgeAuthTest.SECRET, b"plugin", nonce, self.nonce)})

        ok, _ = self.connect(Reflector(None))
        self.assertFalse(ok)

    def test_bridge_that_rejects_our_proof_is_not_used(self):
        self.write_secret(self.SECRET)
        bridge = FakeBridge(self.SECRET, accept=False)
        ok, _ = self.connect(bridge)
        self.assertFalse(ok)
        self.assertIsNone(cln_plugin.bridge_sock)

    def test_bridge_of_another_lsp_is_refused(self):
        self.write_secret(self.SECRET)
        lsp_a, lsp_b = "02" + "a1" * 32, "02" + "b2" * 32
        self.assertTrue(self.connect(FakeBridge(self.SECRET, lsp_pubkey=lsp_a))[0])
        cln_plugin.bridge_sock = None
        other = FakeBridge(self.SECRET, lsp_pubkey=lsp_b)
        ok, _ = self.connect(other)
        self.assertFalse(ok)
        self.assertIsNone(cln_plugin.bridge_sock)
        self.assertTrue(other.closed)
        self.assertTrue(self.connect(FakeBridge(self.SECRET, lsp_pubkey=lsp_a))[0])

    def test_peer_that_only_passes_the_handshake_along_gets_no_link(self):
        self.write_secret(self.SECRET)
        # Something between the plugin and the real bridge forwards the
        # challenge and the response faithfully, so both proofs are genuine.
        # It does not know the session key, so the first line of the
        # session, which it would now have to speak itself, gives it away.
        for how in ("none", "bad"):
            relay = FakeBridge(self.SECRET, ok_mac=how)
            ok, _ = self.connect(relay)
            self.assertFalse(ok, how)
            self.assertIsNone(cln_plugin.bridge_sock)
            self.assertIsNone(cln_plugin.bridge_session)
            self.assertTrue(relay.closed)

    def test_session_keys_and_macs_match_the_bridge_implementation(self):
        # The same fixed values are asserted in the bridge's C tests.
        secret = "00112233445566778899aabbccddeeff" * 2
        key = cln_plugin.session_key(secret, b"\x01" * 32, b"\x02" * 32)
        self.assertEqual(key.hex(),
            "b82c8f11332731da93b2a74578dcd74f3ad5c53f993fa73c6035fbffb026f7bd")
        line = b'{"method":"x"}'
        self.assertEqual(cln_plugin.line_mac(key, b"p2b", 5, line),
            "156441f14fd282e5f8452c617350d874d86aa147c30ae1db48f05c1ad3d9778f")
        self.assertEqual(cln_plugin.line_mac(key, b"b2p", 5, line),
            "a79dbb5cfe974d96c51faa83d5f9660418cc3aaa2aafa87337c5d71587a7ded9")
        self.assertEqual(cln_plugin.line_mac(key, b"p2b", 6, line),
            "1788b7bfdb453e6a307a0824b5aa678b4448fe3c7a6a7f89e09986b08c358ff8")

    def test_every_line_sent_carries_the_next_mac(self):
        self.write_secret(self.SECRET)
        bridge = FakeBridge(self.SECRET)
        self.assertTrue(self.connect(bridge)[0])
        sent_before = len(bridge.raw)
        for n in range(3):
            self.assertTrue(self.real_send_to_bridge({"method": "pay_result",
                                                      "request_id": n}))
        lines = bridge.raw[sent_before:].split(b"\n")[:-1]
        self.assertEqual(len(lines), 3)
        for n, raw in enumerate(lines):
            mac, line = raw.split(b" ", 1)
            self.assertEqual(json.loads(line)["request_id"], n)
            self.assertEqual(mac.decode(),
                             cln_plugin.line_mac(bridge.key, b"p2b", n, line))
        # Without a session nothing is sent.
        cln_plugin.bridge_session = None
        self.assertFalse(self.real_send_to_bridge({"method": "pay_result"}))

    def test_lines_received_must_carry_the_next_mac(self):
        key = b"s" * 32
        session = {"key": key, "tx": 0, "rx": 0}

        def sealed(seq, msg, direction=b"b2p", with_key=key):
            line = json.dumps(msg).encode()
            return cln_plugin.line_mac(with_key, direction, seq, line).encode() \
                + b" " + line

        first = sealed(0, {"method": "htlc_resolve", "n": 0})
        self.assertEqual(cln_plugin.open_line(session, first)["n"], 0)
        self.assertEqual(cln_plugin.open_line(
            session, sealed(1, {"method": "htlc_resolve", "n": 1}))["n"], 1)
        bad = [
            first,                                           # replayed
            sealed(3, {"method": "pay_request"}),            # one was dropped
            sealed(2, {"method": "pay_request"}, with_key=b"x" * 32),
            sealed(2, {"method": "pay_request"}, direction=b"p2b"),  # our own
            sealed(2, {"method": "pay_request"}).replace(b"pay_request",
                                                         b"pay_requesT"),
            b'{"method": "pay_request"}',                    # no MAC at all
            b"",
        ]
        for raw in bad:
            with self.assertRaises(ValueError, msg=raw):
                cln_plugin.open_line(session, raw)
            self.assertEqual(session["rx"], 2)
        # The genuine next line is still accepted afterwards.
        self.assertEqual(cln_plugin.open_line(
            session, sealed(2, {"method": "pay_request"}))["method"], "pay_request")

    def test_reader_drops_the_link_on_a_line_that_is_not_authentic(self):
        self.write_secret(self.SECRET)
        bridge = FakeBridge(self.SECRET)
        self.assertTrue(self.connect(bridge)[0])
        handled = []

        class Stop(Exception):
            pass

        def no_reconnect():
            raise Stop()

        pay = json.dumps({"method": "pay_request", "bolt11": BOLT11,
                          "request_id": 1}).encode()
        good = cln_plugin.line_mac(bridge.key, b"b2p", 1, pay).encode() + b" " + pay
        bridge.inbox = good + b"\n" + pay + b"\n" + good + b"\n"
        with mock.patch.object(cln_plugin, "handle_bridge_msg", handled.append), \
                mock.patch.object(cln_plugin, "connect_bridge", no_reconnect), \
                self.assertRaises(Stop):
            cln_plugin.bridge_reader()
        # The authentic line was acted on; the bare one after it ended the
        # link, so neither it nor anything behind it was.
        self.assertEqual([m["request_id"] for m in handled], [1])
        self.assertIsNone(cln_plugin.bridge_sock)
        self.assertTrue(bridge.closed)

    def test_handshake_has_one_deadline_for_all_of_it(self):
        self.write_secret(self.SECRET)

        class Trickle(FakeBridge):
            """Answers one byte at a time, each just inside the timeout."""
            def __init__(self, test, secret):
                super().__init__(secret)
                self.test = test
                self.timeouts = []

            def settimeout(self, t):
                self.timeouts.append(t)

            def recv(self, n):
                self.test.clock["now"] += 0.5
                return super().recv(n)

        slow = Trickle(self, self.SECRET)
        ok, _ = self.connect(slow)
        self.assertFalse(ok)
        # Each wait was only for what was left of the one deadline.
        waits = [t for t in slow.timeouts if t is not None]
        self.assertTrue(all(t <= cln_plugin.AUTH_TIMEOUT for t in waits))
        self.assertLess(min(waits), 1.0)
        self.assertLessEqual(len(waits), 2 * cln_plugin.AUTH_TIMEOUT + 2)

    def test_secret_is_read_again_on_every_connect(self):
        self.write_secret("aa" * 32)
        self.assertTrue(self.connect(FakeBridge("aa" * 32))[0])
        self.write_secret("bb" * 32)
        self.assertTrue(self.connect(FakeBridge("bb" * 32))[0])
        self.assertFalse(self.connect(FakeBridge("aa" * 32))[0])

    def test_no_connection_without_a_usable_secret_file(self):
        def refused():
            bridge = FakeBridge(self.SECRET)
            ok, create = self.connect(bridge)
            create.assert_not_called()
            return not ok and bridge.raw == b""

        self.assertTrue(refused(), "missing file")
        for text in ("", "short", "zz" * 32, "5c" * 33):
            self.write_secret(text)
            self.assertTrue(refused(), text)
        # Readable by group or others: someone else may know it.
        for mode in (0o640, 0o604, 0o660, 0o644):
            self.write_secret(self.SECRET, mode)
            self.assertTrue(refused(), oct(mode))
        # Owned by another user.
        self.write_secret(self.SECRET)
        with mock.patch.object(cln_plugin.os, "geteuid",
                               return_value=os.geteuid() + 1):
            self.assertTrue(refused(), "foreign owner")
        # A symlink, or not a regular file.
        real = os.path.join(self.dir.name, "real.secret")
        os.rename(self.secret_path, real)
        os.symlink(real, self.secret_path)
        self.assertTrue(refused(), "symlink")
        os.unlink(self.secret_path)
        os.mkdir(self.secret_path)
        self.assertTrue(refused(), "directory")
        os.rmdir(self.secret_path)
        os.rename(real, self.secret_path)
        self.assertTrue(self.connect(FakeBridge(self.SECRET))[0])

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

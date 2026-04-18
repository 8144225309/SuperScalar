# OSS-Fuzz Docker image for SuperScalar.
# Must start from gcr.io/oss-fuzz-base/base-builder (their standard base).

FROM gcr.io/oss-fuzz-base/base-builder

# Build deps. base-builder already provides clang, cmake, git.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlite3-dev \
    libssl-dev \
    autoconf \
    libtool \
    pkg-config \
    zip \
 && rm -rf /var/lib/apt/lists/*

# Pull the SuperScalar source. OSS-Fuzz builds each new commit from main.
RUN git clone --depth 1 https://github.com/8144225309/SuperScalar.git $SRC/SuperScalar

WORKDIR $SRC/SuperScalar
COPY build.sh $SRC/

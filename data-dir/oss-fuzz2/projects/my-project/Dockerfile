FROM gcr.io/oss-fuzz-base/base-builder

# Install build dependencies (keep apt lists for introspector)
RUN apt-get update && apt-get install -y \
    make \
    gcc \
    libjpeg-dev \
    zlib1g-dev \
    libyaml-dev

# Copy source code into container
COPY strparser.h strparser.c $SRC/my-project/

WORKDIR $SRC/my-project
COPY build.sh $SRC/

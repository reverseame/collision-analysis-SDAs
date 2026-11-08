# Reproducible environment for the similarity-preservation experiments.
#
# Pinned SDA implementations (see README.md for the rationale):
#   sdhash        v3.4   (sdhash/sdhash, last public release, Oct 2013)
#   python-ssdeep 3.4.1  (DinoTools/python-ssdeep) on libfuzzy 2.14.1 (Debian bookworm)
#   py-tlsh       4.7.2  (trendmicro/tlsh; no 4.7.1 release exists)
#   unicorn       2.1.3
#
# Build:  docker build -t sda-preservation container
# Run:    see README.md

ARG PYTHON_IMAGE=python:3.11-slim-bookworm

# ---------------------------------------------------------------------------
# sdhash 3.4, linked against Debian's Boost (static) instead of the bundled
# Boost tree, which does not build with a current toolchain.
FROM ${PYTHON_IMAGE} AS sdhash-build
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates git g++ make libssl-dev \
      libboost-system-dev libboost-filesystem-dev \
      libboost-program-options-dev libboost-thread-dev \
 && rm -rf /var/lib/apt/lists/*
ARG SDHASH_COMMIT=db69c8bac406f67fae10b742493d2ed880706bae
RUN git init -q /src/sdhash \
 && git -C /src/sdhash fetch -q --depth 1 https://github.com/sdhash/sdhash.git ${SDHASH_COMMIT} \
 && git -C /src/sdhash checkout -q FETCH_HEAD
WORKDIR /src/sdhash
RUN make -j"$(nproc)" stream \
      CFLAGS="-fPIC -fopenmp -msse4.2 -O3 -fno-strict-aliasing -D_FILE_OFFSET_BITS=64 -D_LARGE_FILE_API -D_DEFAULT_SOURCE" \
      LDFLAGS="-fopenmp -Wl,-Bstatic -lboost_program_options -lboost_filesystem -lboost_thread -lboost_system -Wl,-Bdynamic -lcrypto -lpthread -lm" \
 && strip sdhash
COPY sdhash-pairs.cc /src/sdhash/sdhash-pairs.cc
RUN g++ -O3 -msse4.2 -fopenmp -D_DEFAULT_SOURCE -I. sdhash-pairs.cc libsdbf.a -o sdhash-pairs \
      -Wl,-Bstatic -lboost_filesystem -lboost_thread -lboost_system -Wl,-Bdynamic -lcrypto -lpthread -lm \
 && strip sdhash-pairs

# ---------------------------------------------------------------------------
# Wheels for the source-only Python packages (python-ssdeep, py-tlsh).
FROM ${PYTHON_IMAGE} AS wheels
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git g++ libfuzzy-dev \
 && rm -rf /var/lib/apt/lists/*
# python-ssdeep 3.4.1 imports pkg_resources/distutils from setup.py: build it
# without isolation against a setuptools release that still ships them.
RUN pip install --no-cache-dir "setuptools==69.5.1" "wheel==0.43.0" "cffi==1.17.1"
ARG SSDEEP_COMMIT=becafb0c7607d1b15dff0432f960190dfd672ece
RUN pip wheel --no-cache-dir --no-deps --no-build-isolation -w /wheels \
      "ssdeep @ git+https://github.com/DinoTools/python-ssdeep.git@${SSDEEP_COMMIT}" \
 && pip wheel --no-cache-dir --no-deps -w /wheels "py-tlsh==4.7.2"
# SUM engine (Python 3) at the commit used by reverseame/sum-plugin, with its submodules
# (marked_pefile and its pefile).
ARG SUM_COMMIT=127d4fb93c299bc1b578b30dacd6b5080e48004e
RUN git clone -q https://github.com/reverseame/similarity-unrelocated-module.git /opt/sum \
 && git -C /opt/sum checkout -q ${SUM_COMMIT} \
 && git -C /opt/sum submodule update -q --init --recursive \
 && rm -rf /opt/sum/.git /opt/sum/marked_pefile/.git /opt/sum/marked_pefile/pefile/.git

# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE}
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libfuzzy2 libgomp1 libssl3 \
      texlive-latex-base texlive-latex-recommended texlive-latex-extra \
      texlive-fonts-recommended cm-super dvipng ghostscript \
 && rm -rf /var/lib/apt/lists/*
COPY --from=sdhash-build /src/sdhash/sdhash /src/sdhash/sdhash-pairs /usr/local/bin/
COPY --from=wheels /opt/sum /opt/sum
COPY --from=wheels /wheels /wheels
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir /wheels/*.whl -r /tmp/requirements.txt \
 && rm -rf /wheels /tmp/requirements.txt

ENV MPLCONFIGDIR=/tmp/matplotlib \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/opt/sum
WORKDIR /work
CMD ["bash"]

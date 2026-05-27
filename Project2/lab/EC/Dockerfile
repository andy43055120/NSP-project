FROM ubuntu:24.04 AS ec_base

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    gdb \
    binutils \
    gcc \
    g++ \
    make \
    vim \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /venv
RUN /venv/bin/pip install --no-cache-dir pwntools

ENV PATH="/venv/bin:$PATH"

FROM ec_base AS my_ec

WORKDIR /

COPY exploit.py /exploit
COPY triage.py /triage
COPY grader.sh /grader.sh

RUN chmod +x /exploit /triage /grader.sh

CMD ["/bin/bash"]

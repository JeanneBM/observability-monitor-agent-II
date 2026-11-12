# syntax=docker/dockerfile:1
# Pin the base image by digest in production (Dependabot keeps both tag and digest fresh).
ARG PYTHON_IMAGE=python:3.13-slim

FROM ${PYTHON_IMAGE} AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /wheels .

FROM ${PYTHON_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN groupadd --gid 10001 agentmon \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin agentmon
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
USER 10001:10001
ENTRYPOINT ["agentmon"]
CMD ["watch", "--config", "/etc/agentmon/config.json", "--state", "/var/lib/agentmon"]

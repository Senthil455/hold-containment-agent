FROM public.ecr.aws/docker/library/python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Run the containment runtime as an unprivileged user. The process needs read
# access to the application tree and nothing else.
RUN groupadd --system hold \
    && useradd --system --gid hold --create-home --home-dir /home/hold hold

COPY agent/requirements.txt /app/agent/requirements.txt
RUN python -m pip install --upgrade pip \
    && python -m pip install -r /app/agent/requirements.txt

COPY --chown=hold:hold hold /app/hold
COPY --chown=hold:hold config /app/config
COPY --chown=hold:hold agent /app/agent

USER hold

# AgentCore Runtime supplies the bind address. The application listens on the
# default port used by BedrockAgentCoreApp.
EXPOSE 8080

CMD ["python", "-m", "agent.runtime"]

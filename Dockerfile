FROM public.ecr.aws/docker/library/python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY agent/requirements.txt /app/agent/requirements.txt
RUN python -m pip install --upgrade pip \
    && python -m pip install -r /app/agent/requirements.txt

COPY hold /app/hold
COPY config /app/config
COPY agent /app/agent

# AgentCore Runtime supplies the bind address. The application listens on the
# default port used by BedrockAgentCoreApp.
EXPOSE 8080

CMD ["python", "-m", "agent.runtime"]

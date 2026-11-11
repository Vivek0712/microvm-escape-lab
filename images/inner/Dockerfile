# Inner cage: the microVM the agent tries to escape from.
# Built on the Lambda-managed AL2023 base (snapshot-safe), ARM64 (Graviton).
FROM public.ecr.aws/lambda/microvms:al2023-minimal

RUN dnf install -y python3.12 python3.12-pip && dnf clean all
# boto3 is present so the control-plane, credential, and LLM-brain probes are
# real; the execution role is what actually decides whether those calls succeed.
RUN python3.12 -m pip install --no-cache-dir boto3

WORKDIR /app
# microvm_hooks.py is injected into the build context root by the builder.
COPY microvm_hooks.py app.py /app/
COPY lab /app/lab
RUN mkdir -p /opt/agent /work && echo "placeholder" > /opt/agent/.localflag

EXPOSE 8080
ENTRYPOINT ["python3.12", "/app/app.py"]

# Outer warden: holds the flag, mirrors the log, renders the verdict.
# Built on the Lambda-managed AL2023 base, ARM64 (Graviton).
FROM public.ecr.aws/lambda/microvms:al2023-minimal

RUN dnf install -y python3.12 && dnf clean all

WORKDIR /app
# microvm_hooks.py is injected into the build context root by the builder.
COPY microvm_hooks.py app.py /app/
COPY lab /app/lab

EXPOSE 8080
ENTRYPOINT ["python3.12", "/app/app.py"]

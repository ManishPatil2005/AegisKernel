FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn pydantic z3-solver

COPY agency/ /app/agency/

EXPOSE 8500

CMD ["python", "agency/company/server.py"]

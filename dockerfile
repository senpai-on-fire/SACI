# Build stage
FROM node:21 AS frontend-build
WORKDIR /build
COPY web/package*.json ./
RUN npm install --force
COPY web/ ./
RUN npm run build

# Runtime stage
FROM python:3.13
WORKDIR /app
COPY --from=frontend-build /build/dist /app/web/dist
COPY saci/ /app/saci/
COPY saci-database/ /app/saci-database/
COPY pyproject.toml ./
RUN pip install . './saci-database'
CMD ["uvicorn", "saci.webui.web:app", "--host", "0.0.0.0", "--port", "8000"]

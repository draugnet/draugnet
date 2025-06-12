FROM python:3.12-slim


WORKDIR /app
COPY . .
RUN bash install.sh

CMD ["fastapi", "run", "main.py"]
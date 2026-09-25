FROM apify/actor-python:3.13

# System deps: git for pip install from source, chromium for screenshots
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    chromium \
    && rm -rf /var/lib/apt/lists/*

# Install theHarvester pinned to a release. The pin and the FROM line above are moved by
# .github/workflows/theharvester-update.yml, which smoke-tests a new release before shipping it.
RUN pip install --no-cache-dir git+https://github.com/laramies/theHarvester.git@4.11.1

# Create config dir where theHarvester expects api-keys.yaml + proxies.yaml
RUN mkdir -p /root/.theHarvester

# Copy actor source
COPY requirements.txt /actor/requirements.txt
RUN pip install --no-cache-dir -r /actor/requirements.txt

COPY . /actor
WORKDIR /actor

CMD ["python3", "-m", "src.main"]

FROM apify/actor-python:3.13

# System deps: git for pip install from source, chromium for screenshots
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    chromium \
    && rm -rf /var/lib/apt/lists/*

# Install theHarvester pinned to a release: upstream master moved to requires-python>=3.14 (2026-09),
# which the 3.13 base image cannot satisfy, and unpinned master broke the build silently.
RUN pip install --no-cache-dir git+https://github.com/laramies/theHarvester.git@4.11.1

# Create config dir where theHarvester expects api-keys.yaml + proxies.yaml
RUN mkdir -p /root/.theHarvester

# Copy actor source
COPY requirements.txt /actor/requirements.txt
RUN pip install --no-cache-dir -r /actor/requirements.txt

COPY . /actor
WORKDIR /actor

CMD ["python3", "-m", "src.main"]

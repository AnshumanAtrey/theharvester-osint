FROM apify/actor-python:3.13

# git for pip install from source
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# Install theHarvester pinned to a release. The pin and the FROM line above are moved by
# .github/workflows/theharvester-update.yml, which smoke-tests a new release before shipping it.
RUN pip install --no-cache-dir git+https://github.com/laramies/theHarvester.git@4.11.1

# theHarvester's --screenshot uses Playwright's own browser (not a system Chromium). Installing it
# through the Playwright that theHarvester pins keeps the browser version matched after upgrades.
RUN python -m playwright install --with-deps --only-shell chromium

# Create config dir where theHarvester expects api-keys.yaml + proxies.yaml
RUN mkdir -p /root/.theHarvester

# Copy actor source
COPY requirements.txt /actor/requirements.txt
RUN pip install --no-cache-dir -r /actor/requirements.txt

COPY . /actor
WORKDIR /actor

CMD ["python3", "-m", "src.main"]

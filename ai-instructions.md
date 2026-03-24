Please extend the pattern shown in the examples to this plugin repository. Specifically take every test in .travis.yml and ensure it is run in github actions. Add any files needed. Pay special attention to following the patterns in the example diffs. If you need to see any code from those repos (.ci, kafka and elasticsearch output plugins) they are on disk at the same level as this plugin. You can use the action run cli to test if your solution works.

The .ci repo has the shared actions:
```
diff --git a/.github/workflows/integration-tests.yml b/.github/workflows/integration-tests.yml
new file mode 100644
index 0000000..5bcb477
--- /dev/null
+++ b/.github/workflows/integration-tests.yml
@@ -0,0 +1,46 @@
+name: Integration Tests
+
+on:
+  workflow_call:
+    inputs:
+      timeout-minutes:
+        description: 'Timeout for the test step in minutes'
+        type: number
+        default: 60
+
+permissions:
+  contents: read
+
+jobs:
+  integration-tests:
+    name: Integration Test - ES ${{ matrix.elastic-stack-version }} ${{ matrix.snapshot && '(Snapshot)' || '' }}
+    runs-on: ubuntu-latest
+    strategy:
+      fail-fast: false
+      matrix:
+        elastic-stack-version:
+          - '8.current'
+          - '9.current'
+        snapshot: [false, true]
+        include:
+          - elastic-stack-version: '9.next'
+            snapshot: true
+          - elastic-stack-version: 'main'
+            snapshot: true
+
+    steps:
+      - name: Checkout code
+        uses: actions/checkout@v6
+
+      - name: Setup test environment
+        id: setup
+        uses: logstash-plugins/.ci/setup@feature/github-actions
+        with:
+          elastic-stack-version: ${{ matrix.elastic-stack-version }}
+          snapshot: ${{ matrix.snapshot }}
+          integration: true
+
+      - name: Run integration tests
+        if: steps.setup.outputs.skip != 'true'
+        timeout-minutes: ${{ inputs.timeout-minutes }}
+        run: bash .ci/docker-run.sh
diff --git a/.github/workflows/performance.yml b/.github/workflows/performance.yml
new file mode 100644
index 0000000..a29ea98
--- /dev/null
+++ b/.github/workflows/performance.yml
@@ -0,0 +1,56 @@
+name: performance
+
+on:
+  workflow_call:
+
+## Concurrency only allowed in the main branch.
+## So old builds running for old commits within the same Pull Request are cancelled
+concurrency:
+  group: ${{ github.workflow }}-${{ github.ref }}
+  cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}
+
+permissions:
+  contents: read
+
+jobs:
+  performance:
+    name: Performance - ES ${{ matrix.elastic-stack-version }} ${{ matrix.snapshot && '(Snapshot)' || '' }}
+    # Only run performance tests if HAS_PERFORMANCE_TESTS is set to 1
+    if: vars.HAS_PERFORMANCE_TESTS == '1'
+    runs-on: ubuntu-latest
+    strategy:
+      fail-fast: false
+      matrix:
+        elastic-stack-version:
+          - '8.current'
+          - '9.previous'
+          - '9.current'
+          - 'main'
+        snapshot: [false, true]
+        docker-env: ['dockerjdk21.env']
+        exclude:
+          # main only runs as snapshot
+          - elastic-stack-version: 'main'
+            snapshot: false
+
+    steps:
+      - name: Checkout code
+        uses: actions/checkout@v6
+
+      - name: Setup test environment
+        id: setup
+        uses: logstash-plugins/.ci/setup@feature/github-actions
+        with:
+          elastic-stack-version: ${{ matrix.elastic-stack-version }}
+          snapshot: ${{ matrix.snapshot }}
+          docker-env: ${{ matrix.docker-env }}
+
+      - name: Run performance tests
+        if: steps.setup.outputs.skip != 'true'
+        run: |
+          bash .ci/performance/docker-setup.sh
+          bash .ci/performance/docker-run.sh
+        env:
+          ELASTIC_STACK_VERSION: ${{ matrix.elastic-stack-version }}
+          SNAPSHOT: ${{ matrix.snapshot }}
+          DOCKER_ENV: ${{ matrix.docker-env }}
diff --git a/.github/workflows/secure-integration-tests.yml b/.github/workflows/secure-integration-tests.yml
new file mode 100644
index 0000000..7634399
--- /dev/null
+++ b/.github/workflows/secure-integration-tests.yml
@@ -0,0 +1,82 @@
+name: Secure Integration Tests
+
+on:
+  workflow_call:
+    inputs:
+      timeout-minutes:
+        description: 'Timeout for the test step in minutes'
+        type: number
+        default: 60
+
+permissions:
+  contents: read
+
+jobs:
+  secure-integration-tests:
+    name: Secure Integration Test - ES ${{ matrix.elastic-stack-version }} ${{ matrix.snapshot && '(Snapshot)' || '' }}${{ matrix.es-ssl-key-invalid == 'true' && ' (Invalid SSL)' || '' }}${{ matrix.es-ssl-supported-protocols != '' && format(' ({0})', matrix.es-ssl-supported-protocols) || '' }}
+    runs-on: ubuntu-latest
+    strategy:
+      fail-fast: false
+      matrix:
+        elastic-stack-version:
+          - '8.current'
+          - '9.current'
+        snapshot: [false]
+        es-ssl-key-invalid: ['false']
+        es-ssl-supported-protocols: ['']
+        include:
+          # SSL key invalid variants
+          - elastic-stack-version: '8.current'
+            snapshot: false
+            es-ssl-key-invalid: 'true'
+            es-ssl-supported-protocols: ''
+          - elastic-stack-version: '9.current'
+            snapshot: false
+            es-ssl-key-invalid: 'true'
+            es-ssl-supported-protocols: ''
+          # TLSv1.3 variants
+          - elastic-stack-version: '8.current'
+            snapshot: false
+            es-ssl-key-invalid: 'false'
+            es-ssl-supported-protocols: 'TLSv1.3'
+          - elastic-stack-version: '9.current'
+            snapshot: false
+            es-ssl-key-invalid: 'false'
+            es-ssl-supported-protocols: 'TLSv1.3'
+          # Snapshot variants
+          - elastic-stack-version: '8.current'
+            snapshot: true
+            es-ssl-key-invalid: 'false'
+            es-ssl-supported-protocols: ''
+          - elastic-stack-version: '9.current'
+            snapshot: true
+            es-ssl-key-invalid: 'false'
+            es-ssl-supported-protocols: ''
+          - elastic-stack-version: '9.next'
+            snapshot: true
+            es-ssl-key-invalid: 'false'
+            es-ssl-supported-protocols: ''
+          - elastic-stack-version: 'main'
+            snapshot: true
+            es-ssl-key-invalid: 'false'
+            es-ssl-supported-protocols: ''
+
+    steps:
+      - name: Checkout code
+        uses: actions/checkout@v6
+
+      - name: Setup test environment
+        id: setup
+        uses: logstash-plugins/.ci/setup@feature/github-actions
+        with:
+          elastic-stack-version: ${{ matrix.elastic-stack-version }}
+          snapshot: ${{ matrix.snapshot }}
+          integration: true
+          secure-integration: true
+          es-ssl-key-invalid: ${{ matrix.es-ssl-key-invalid }}
+          es-ssl-supported-protocols: ${{ matrix.es-ssl-supported-protocols }}
+
+      - name: Run secure integration tests
+        if: steps.setup.outputs.skip != 'true'
+        timeout-minutes: ${{ inputs.timeout-minutes }}
+        run: bash .ci/docker-run.sh
diff --git a/.github/workflows/test-setup.yml b/.github/workflows/test-setup.yml
new file mode 100644
index 0000000..c8d6a35
--- /dev/null
+++ b/.github/workflows/test-setup.yml
@@ -0,0 +1,31 @@
+name: test-setup
+
+on:
+  pull_request:
+    branches:
+      - "1.x"
+
+## Concurrency only allowed in the 1.x branch.
+## So old builds running for old commits within the same Pull Request are cancelled
+concurrency:
+  group: ${{ github.workflow }}-${{ github.ref }}
+  cancel-in-progress: ${{ github.ref != 'refs/heads/1.x' }}
+
+permissions:
+  contents: read
+
+jobs:
+  test-setup-action:
+    runs-on: ubuntu-latest
+    steps:
+      - uses: actions/checkout@v6
+
+      - uses: ./setup
+        id: setup
+        continue-on-error: true
+        with:
+          elastic-stack-version: "9.current"
+          snapshot: false
+
+      - name: Assert is failure (Gemfile is not available in the .ci repository)
+        run: test "${{steps.setup.outcome}}" = "failure"
diff --git a/.github/workflows/test.yml b/.github/workflows/test.yml
new file mode 100644
index 0000000..023181f
--- /dev/null
+++ b/.github/workflows/test.yml
@@ -0,0 +1,51 @@
+name: Test
+
+on:
+  workflow_call:
+    inputs:
+      timeout-minutes:
+        description: 'Timeout for the test step in minutes'
+        type: number
+        default: 60
+
+permissions:
+  contents: read
+
+jobs:
+  test:
+    name: Test - ES ${{ matrix.elastic-stack-version }}${{ matrix.snapshot && ' (Snapshot)' || '' }}
+    runs-on: ubuntu-latest
+    strategy:
+      fail-fast: false
+      matrix:
+        elastic-stack-version:
+          - '8.current'
+          - '9.previous'
+          - '9.current'
+          - '9.next'
+          - 'main'
+        snapshot: [false, true]
+        docker-env: ['dockerjdk21.env']
+        exclude:
+          # 9.next and main only run as snapshot
+          - elastic-stack-version: '9.next'
+            snapshot: false
+          - elastic-stack-version: 'main'
+            snapshot: false
+
+    steps:
+      - name: Checkout code
+        uses: actions/checkout@v6
+
+      - name: Setup test environment
+        id: setup
+        uses: logstash-plugins/.ci/setup@feature/github-actions
+        with:
+          elastic-stack-version: ${{ matrix.elastic-stack-version }}
+          snapshot: ${{ matrix.snapshot }}
+          docker-env: ${{ matrix.docker-env }}
+
+      - name: Run tests
+        if: steps.setup.outputs.skip != 'true'
+        timeout-minutes: ${{ inputs.timeout-minutes }}
+        run: bash .ci/docker-run.sh
diff --git a/setup/README.md b/setup/README.md
new file mode 100644
index 0000000..f65fb85
--- /dev/null
+++ b/setup/README.md
@@ -0,0 +1,44 @@
+# <!--name-->Setup Test Environment<!--/name-->
+
+[![usages](https://img.shields.io/badge/usages-white?logo=githubactions&logoColor=blue)](https://github.com/search?q=logstash-plugins%2F.ci%2Fsetup+%28path%3A.github%2Fworkflows+OR+path%3A**%2Faction.yml+OR+path%3A**%2Faction.yaml%29&type=code)
+[![test-setup](https://github.com/logstash-plugins/.ci/actions/workflows/test-setup.yml/badge.svg?branch=main)](https://github.com/logstash-plugins/.ci/workflows/test-setup.yml)
+
+<!--description-->
+Common setup steps for unit, integration and secure integration tests
+<!--/description-->
+
+## Inputs
+
+<!--inputs-->
+| Name                         | Description                                     | Required | Default |
+|------------------------------|-------------------------------------------------|----------|---------|
+| `elastic-stack-version`      | Elasticsearch stack version to test against     | `true`   | ` `     |
+| `snapshot`                   | Whether to use snapshot version                 | `false`  | `false` |
+| `docker-env`                 | Docker environment file (e.g., dockerjdk21.env) | `false`  | ` `     |
+| `integration`                | Enable integration testing                      | `false`  | `false` |
+| `secure-integration`         | Enable secure integration testing               | `false`  | `false` |
+| `es-ssl-key-invalid`         | Use invalid SSL key for testing                 | `false`  | `false` |
+| `es-ssl-supported-protocols` | SSL/TLS protocols to test                       | `false`  | ` `     |
+<!--/inputs-->
+
+## Outputs
+<!--outputs-->
+| Name   | Description                        |
+|--------|------------------------------------|
+| `skip` | Whether the test should be skipped |
+<!--/outputs-->
+
+## Usage
+
+<!--usage action="logstash-plugins/.ci/**" version="env:VERSION"-->
+```yaml
+jobs:
+  federation:
+    permissions:
+      contents: 'read'
+    steps:
+      - uses: actions/checkout@v6
+
+      - uses: logstash-plugins/.ci/setup@v1
+```
+<!--/usage-->
diff --git a/setup/action.yml b/setup/action.yml
new file mode 100644
index 0000000..c9c0e91
--- /dev/null
+++ b/setup/action.yml
@@ -0,0 +1,116 @@
+name: 'Setup Test Environment'
+description: 'Common setup steps for unit, integration and secure integration tests'
+
+inputs:
+  elastic-stack-version:
+    description: 'Elasticsearch stack version to test against'
+    required: true
+  snapshot:
+    description: 'Whether to use snapshot version'
+    required: false
+    default: 'false'
+  docker-env:
+    description: 'Docker environment file (e.g., dockerjdk21.env)'
+    required: false
+    default: ''
+  integration:
+    description: 'Enable integration testing'
+    required: false
+    default: 'false'
+  secure-integration:
+    description: 'Enable secure integration testing'
+    required: false
+    default: 'false'
+  es-ssl-key-invalid:
+    description: 'Use invalid SSL key for testing'
+    required: false
+    default: 'false'
+  es-ssl-supported-protocols:
+    description: 'SSL/TLS protocols to test'
+    required: false
+    default: ''
+
+outputs:
+  skip:
+    description: 'Whether the test should be skipped'
+    value: ${{ steps.docker_setup.outputs.skip }}
+
+runs:
+  using: 'composite'
+  steps:
+    - name: Set up environment variables
+      shell: bash
+      env:
+        ELASTIC_STACK_VERSION: ${{ inputs.elastic-stack-version }}
+        SNAPSHOT: ${{ inputs.snapshot }}
+        DOCKER_ENV: ${{ inputs.docker-env }}
+        INTEGRATION: ${{ inputs.integration }}
+        SECURE_INTEGRATION: ${{ inputs.secure-integration }}
+        ES_SSL_KEY_INVALID: ${{ inputs.es-ssl-key-invalid }}
+        ES_SSL_SUPPORTED_PROTOCOLS: ${{ inputs.es-ssl-supported-protocols }}
+      run: |
+        echo "LOG_LEVEL=info" >> $GITHUB_ENV
+        echo "ELASTIC_STACK_VERSION=${ELASTIC_STACK_VERSION}" >> $GITHUB_ENV
+
+        if [ "${SNAPSHOT}" = "true" ]; then
+          echo "SNAPSHOT=true" >> $GITHUB_ENV
+        fi
+
+        if [ -n "${DOCKER_ENV}" ]; then
+          echo "DOCKER_ENV=${DOCKER_ENV}" >> $GITHUB_ENV
+        fi
+
+        if [ "${INTEGRATION}" = "true" ]; then
+          echo "INTEGRATION=true" >> $GITHUB_ENV
+        fi
+
+        if [ "${SECURE_INTEGRATION}" = "true" ]; then
+          echo "SECURE_INTEGRATION=true" >> $GITHUB_ENV
+        fi
+
+        if [ "${ES_SSL_KEY_INVALID}" = "true" ]; then
+          echo "ES_SSL_KEY_INVALID=true" >> $GITHUB_ENV
+        fi
+
+        if [ -n "${ES_SSL_SUPPORTED_PROTOCOLS}" ]; then
+          echo "ES_SSL_SUPPORTED_PROTOCOLS=${ES_SSL_SUPPORTED_PROTOCOLS}" >> $GITHUB_ENV
+        fi
+
+    - name: Setup Docker Buildx
+      uses: docker/setup-buildx-action@v3
+
+    - name: Bootstrap CI assets
+      shell: bash
+      run: |
+        mkdir -p .ci
+        curl -sL https://github.com/logstash-plugins/.ci/archive/1.x.tar.gz | \
+        sh -c 'if tar --version 2>/dev/null | grep -q "GNU tar"; then
+          TAR_KEEP="--skip-old-files"; TAR_WILDCARDS="--wildcards";
+        else
+          TAR_KEEP="-k"; TAR_WILDCARDS="";
+        fi; tar -xzvf - $TAR_KEEP --strip-components=1 -C .ci $TAR_WILDCARDS "*Dockerfile*" "*docker*" "*.sh" "*logstash-versions*"'
+
+    - name: Run docker-setup.sh
+      id: docker_setup
+      shell: bash {0}
+      run: |
+        set +e
+        .ci/docker-setup.sh
+        exit_code=$?
+        case $exit_code in
+          0)
+            echo "Install succeeded."
+            ;;
+          2)
+            echo "::error::Failed to pull logstash-${ELASTIC_STACK_VERSION}. The image should exist. Aborting build."
+            exit $exit_code
+            ;;
+          99)
+            echo "::notice::Failed to pull logstash-${ELASTIC_STACK_VERSION}. Likely due to missing DRA build."
+            echo "skip=true" >> $GITHUB_OUTPUT
+            ;;
+          *)
+            echo "::error::Install failed with an unexpected code: $exit_code. Stopping build."
+            exit $exit_code
+            ;;
+        esac
diff --git a/travis/matrix.yml b/travis/matrix.yml
index d4a8ca2..22d37b4 100644
--- a/travis/matrix.yml
+++ b/travis/matrix.yml
@@ -19,7 +19,6 @@ env:
     - ELASTIC_STACK_VERSION=9.previous DOCKER_ENV=dockerjdk21.env
     - ELASTIC_STACK_VERSION=8.current DOCKER_ENV=dockerjdk21.env
     - SNAPSHOT=true ELASTIC_STACK_VERSION=main DOCKER_ENV=dockerjdk21.env
-    - SNAPSHOT=true ELASTIC_STACK_VERSION=9.next DOCKER_ENV=dockerjdk21.env
     - SNAPSHOT=true ELASTIC_STACK_VERSION=9.current DOCKER_ENV=dockerjdk21.env
     - SNAPSHOT=true ELASTIC_STACK_VERSION=9.previous DOCKER_ENV=dockerjdk21.env
     - SNAPSHOT=true ELASTIC_STACK_VERSION=8.current DOCKER_ENV=dockerjdk21.env
@@ -33,7 +32,5 @@ jobs:
   env: ELASTIC_STACK_VERSION=9.current DOCKER_ENV=dockerjdk21.env
 - <<: *_performance
   env: ELASTIC_STACK_VERSION=9.previous DOCKER_ENV=dockerjdk21.env
-- <<: *_performance
-  env: SNAPSHOT=true ELASTIC_STACK_VERSION=9.next DOCKER_ENV=dockerjdk21.env
 - <<: *_performance
   env: SNAPSHOT=true ELASTIC_STACK_VERSION=main DOCKER_ENV=dockerjdk21.env
```

The kafka plugin refactor:
```
diff --git a/.github/workflows/tests.yml b/.github/workflows/tests.yml
new file mode 100644
index 0000000..11ca7a4
--- /dev/null
+++ b/.github/workflows/tests.yml
@@ -0,0 +1,17 @@
+name: Tests
+
+on:
+  push:
+  pull_request:
+    branches:
+      - main
+  workflow_dispatch:
+
+jobs:
+  tests:
+    uses: logstash-plugins/.ci/.github/workflows/test.yml@feature/github-actions
+    concurrency:
+      group: ${{ github.workflow }}-${{ github.ref }}
+      cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}
+    with:
+      timeout-minutes: 90
```

The es output plugin:
```
diff --git a/.github/workflows/integration-tests.yml b/.github/workflows/integration-tests.yml
new file mode 100644
index 0000000..43a105d
--- /dev/null
+++ b/.github/workflows/integration-tests.yml
@@ -0,0 +1,17 @@
+name: Integration Tests
+
+on:
+  push:
+  pull_request:
+    branches:
+      - main
+  workflow_dispatch:
+
+jobs:
+  integration-tests:
+    uses: logstash-plugins/.ci/.github/workflows/integration-tests.yml@feature/github-actions
+    concurrency:
+      group: ${{ github.workflow }}-${{ github.ref }}
+      cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}
+    with:
+      timeout-minutes: 60
diff --git a/.github/workflows/secure-integration-tests.yml b/.github/workflows/secure-integration-tests.yml
new file mode 100644
index 0000000..44e42b2
--- /dev/null
+++ b/.github/workflows/secure-integration-tests.yml
@@ -0,0 +1,17 @@
+name: Secure Integration Tests
+
+on:
+  push:
+  pull_request:
+    branches:
+      - main
+  workflow_dispatch:
+
+jobs:
+  secure-integration-tests:
+    uses: logstash-plugins/.ci/.github/workflows/secure-integration-tests.yml@feature/github-actions
+    concurrency:
+      group: ${{ github.workflow }}-${{ github.ref }}
+      cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}
+    with:
+      timeout-minutes: 60
diff --git a/.github/workflows/tests.yml b/.github/workflows/tests.yml
new file mode 100644
index 0000000..4efed20
--- /dev/null
+++ b/.github/workflows/tests.yml
@@ -0,0 +1,17 @@
+name: Unit Tests
+
+on:
+  push:
+  pull_request:
+    branches:
+      - main
+  workflow_dispatch:
+
+jobs:
+  tests:
+    uses: logstash-plugins/.ci/.github/workflows/test.yml@feature/github-actions
+    concurrency:
+      group: ${{ github.workflow }}-${{ github.ref }}
+      cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}
+    with:
+      timeout-minutes: 60
diff --git a/spec/unit/outputs/elasticsearch_spec.rb b/spec/unit/outputs/elasticsearch_spec.rb
index 3f74785..572c207 100644
--- a/spec/unit/outputs/elasticsearch_spec.rb
+++ b/spec/unit/outputs/elasticsearch_spec.rb
@@ -901,6 +901,9 @@ describe LogStash::Outputs::ElasticSearch do

     before(:each) do
       allow(elasticsearch_output_instance.client).to receive(:logger).and_return(logger_stub)
+      # Stub the output plugin's own @logger to prevent submit()/retrying_submit()
+      # from logging the full 15MB action payload on each retry, which floods stdout.
+      elasticsearch_output_instance.instance_variable_set(:@logger, logger_stub)

       allow(elasticsearch_output_instance.client).to receive(:bulk).and_call_original

```
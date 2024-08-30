
# Note: Windows stores virtual environment scripts under Scripts/ directory instead of bin/
venv_bin := if os_family() == "windows" { ".venv/Scripts" } else { ".venv/bin" }

# Install python virtual environment
venv:
    [ -d .venv ] || python3 -m venv .venv
    {{venv_bin}}/pip3 install .

# Install dev dependencies
install_dev:
    {{venv_bin}}/pip3 install pylint black

# Run formatting and linting
lint:
    {{venv_bin}}/python3 -m black .
    {{venv_bin}}/python3 -m pylint AWS

# Check formatting
check-format:
    {{venv_bin}}/python3 -m black --check .

# Check linting
check-lint:
    {{venv_bin}}/python3 -m pylint AWS

# Run tests
test *args='':
    {{venv_bin}}/python3 -m robot.run --outputdir output {{args}} tests

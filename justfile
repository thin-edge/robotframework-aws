
# Note: Windows stores virtual environment scripts under Scripts/ directory instead of bin/
# and uses 'python'/'pip' instead of 'python3'/'pip3'
venv_bin := if os_family() == "windows" { ".venv/Scripts" } else { ".venv/bin" }
python := if os_family() == "windows" { "python" } else { "python3" }
pip := if os_family() == "windows" { "pip" } else { "pip3" }

# Install python virtual environment
venv:
    [ -d .venv ] || {{python}} -m venv .venv
    {{venv_bin}}/{{pip}} install .

# Install dev dependencies
install_dev:
    {{venv_bin}}/{{pip}} install pylint black

# Run formatting and linting
lint:
    {{venv_bin}}/{{python}} -m black .
    {{venv_bin}}/{{python}} -m pylint AWS

# Check formatting
check-format:
    {{venv_bin}}/{{python}} -m black --check .

# Check linting
check-lint:
    {{venv_bin}}/{{python}} -m pylint AWS

# Run tests
test *args='':
    {{venv_bin}}/{{python}} -m robot.run --outputdir output {{args}} tests

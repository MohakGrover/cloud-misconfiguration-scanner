# Documentation: `rules_engine/`

## Overview
The `rules_engine/` package is responsible for loading detection rules and applying them to the data collected by scanners.

## Check Logic
The engine supports a recursive condition model:
- **Condition**: `all` (AND) or `any` (OR).
- **Checks**: A list of field checks or nested conditions.

## Classes

### `RuleLoader` (`rules_engine/loader.py`)
- **Purpose**: Loads rule definitions from YAML files.
- **Logic**:
    - Recursively walks the `rules/` directory.
    - Parses files ending in `.yaml` or `.yml`.
    - Filters rules by `provider` if specified.
- **Output**: A list of rule dictionaries.

### `RuleEvaluator` (`rules_engine/evaluator.py`)
- **Purpose**: Matches resources against rules to generate findings.
- **Methods**:
    - `evaluate(rules, resources)`:
        - Iterates through rules and resources.
        - Matches `provider` and `service`.
        - Calls `_check_condition` to verify compliance.
        - Returns a list of `finding` dictionaries.
    - `_check_condition(logic, resource)`:
        - Recursive function to evaluate `all`/`any` logic.
    - `_get_field_value(resource, path)`:
        - Helper to access nested dictionary keys using dot notation (e.g., `public_access_block.BlockPublicAcls`).
- **Supported Operators**:
    - `equals`, `not_equals`
    - `contains`
    - `exists`, `not_exists`
    - `gt`, `lt`

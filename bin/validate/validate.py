"""Validates atomics based on JSON Schema."""
import glob
import os.path

import yaml
from jsonschema import validate
from jsonschema.exceptions import ValidationError

with open(f"{os.path.dirname(os.path.abspath(__file__))}/atomic-red-team.schema.yaml", "r") as f:
    schema = yaml.safe_load(f)

    for item in glob.glob("./atomics/T*/T*.yaml"):
        with open(item, 'r') as file:
            data = yaml.safe_load(file)
        try:
            validate(
                instance=data,
                schema=schema
            )
        except ValidationError as ve:
            print(f"Error occurred with {item}.")
            print("Each of the following are why it failed:")
            print(f"\n\t{ve.context[0].message}\n")
            print(f"The JSON Path is {ve.json_path}")
        except Exception as e:
            print(f"Error occurred with {item}.")
            print("Each of the following are why it failed:")
            print(f"\n\t{e}\n")

from typing import Dict, List, Literal, Optional, Union

from pydantic import BaseModel, Field, validator, IPvAnyAddress, AnyUrl, constr, FileUrl

Platform = Literal[
    "windows", "macos", "linux", "office-365", "azure-ad", "google-workspace", "saas", "iaas", "containers", "iaas:gcp", "iaas:azure", "iaas:aws"]
Executor = Literal["manual", "powershell", "pwsh", "sh", "command_prompt", "bash"]
DependencyExecutor = Literal["command_prompt", "powershell", "sh", "bash", "manual"]


class AtomicDependency(BaseModel):
    prereq_command: Optional[str]
    get_prereq_command: Optional[str]
    description: str


class AtomicExecutor(BaseModel):
    name: Executor
    steps: Optional[str]
    command: Optional[str]
    cleanup: Optional[str] = Field(default=None, alias="cleanup_command")
    elevation_required: Optional[bool]


class URLValidator(BaseModel):
    url: Union[IPvAnyAddress, AnyUrl, FileUrl, constr(
        regex="^(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\.?(:\d{1,5})?$")]


# TODO: Add a regex for path validation
class PathValidator(BaseModel):
    path: constr(
        regex="^(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\.?(:\d{1,5})?$")


class InputArgument(BaseModel):
    description: str
    type: Literal["path", "url", "string", "integer"]
    default: Optional[str]

    @validator('default')
    def default_must_be_of_valid_type(cls, v, values, **kwargs):
        if (_type := values.get("type")) and v:
            if _type == "integer":
                try:
                    int(v)
                except ValueError:
                    raise ValueError(f"{v} is not a valid integer.")
            elif _type == "url":
                try:
                    URLValidator(url=v)
                except ValueError as e:
                    if not v.startswith("file://"):  # TODO: Add a regex for file schema validation
                        raise ValueError(f"{v} is neither a valid IPv4/IPv6 address nor a valid Url.")
            elif _type == "path":
                # try:
                #     PathValidator(path=v)
                # except ValueError as e:
                #     raise ValueError(f"{v} is not a valid path.")
                pass

        return v


class AtomicTest(BaseModel):
    name: str
    description: str
    platforms: List[Platform] = Field(..., alias="supported_platforms")
    executor: AtomicExecutor
    dependencies: Optional[List[AtomicDependency]]
    dependency_executor_name: Optional[DependencyExecutor]
    input_arguments: Optional[Dict[str, InputArgument]]


class AtomicTechnique(BaseModel):
    technique: str = Field(..., regex="T[\.\d]{4,8}", alias="attack_technique")
    name: str = Field(..., alias="display_name")
    tests: List[AtomicTest] = Field(..., alias="atomic_tests")

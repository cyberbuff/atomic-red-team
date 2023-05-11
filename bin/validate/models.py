from pydantic import BaseModel, Field, validator, ValidationError
from typing import Dict, List, Literal, Optional

Platform = Literal["windows","macos","linux","office-365","azure-ad","google-workspace","saas","iaas","containers","iaas:gcp","iaas:azure","iaas:aws"]
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


class InputArgument(BaseModel):
    description: str
    type: Literal["path", "url", "string", "integer"]
    default: Optional[str]

    @validator('default')
    def default_must_be_of_valid_type(cls, v, values, **kwargs):
        if _type := values.get("type"):
            if _type == "integer":
                try: 
                    int(v)
                except ValueError as e:
                    raise ValidationError(str(e))
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

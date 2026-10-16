# Windows software requirements — sec-data

## Purpose and scope

Minimum workstation software to run the two local JSON generators, develop/debug them in VS Code, run unit tests, and *optionally* upload generated files to AWS DynamoDB. Data generation is offline and does not need AWS credentials.

## Required for local data generation

| Component | Requirement | Notes |
| --- | --- | --- |
| Windows | Windows 10 or Windows 11 | PowerShell instructions and examples target Windows. |
| Python | **Python 3.12**, 64-bit recommended | Project CI targets 3.12. Other releases are not formally validated. |
| Shell | Windows PowerShell 5.1 or PowerShell 7+ | Use PowerShell syntax in the instructions. |
| Source checkout | Git for Windows | Needed to clone/update source; not required after files are already present. |
| Disk | Enough free space for Python venv and JSON exports | Depends on installed Python and generated data volume. |
| Internet | Needed for initial installation/cloning | **Not** required to generate data after dependencies/source are present. |

The generators rely on the Python **standard library** only. The Python `unittest` suite also runs without AWS access.

## Recommended for development

| Software | Purpose |
| --- | --- |
| Visual Studio Code | Editing, integrated terminal, Testing panel, breakpoints |
| VS Code Python extension (Microsoft) | Interpreter selection and unittest discovery |
| VS Code Python Debugger extension (Microsoft) | Debugging with breakpoints/F5 |
| Pylance (Microsoft) | Code analysis and autocomplete |

Create a virtual environment with `py -3.12 -m venv .venv` and select `.venv\Scripts\python.exe` in VS Code.

## Optional for AWS upload **only**

- Python package `boto3`: install into the chosen venv with `python -m pip install boto3`.
- AWS CLI v2: recommended to configure and list named profiles (e.g., `aws configure list-profiles`). The uploader itself uses boto3, not subprocess calls to the AWS CLI.
- Valid credentials in a shared AWS profile; IAM permissions to call `sts:GetCallerIdentity` and perform DynamoDB table description, creation (when needed), item batch writing and related access in the target region. Permissions vary according to whether the table already exists.
- AWS network connectivity and an intended AWS region. DynamoDB **on-demand capacity costs money**.
- The uploader displays the target AWS account, region, table and count and requires typing `UPLOAD`; optional `--yes` bypasses this safeguard.

## Not required

- EC2, Docker, Linux/WSL, a running vulnerability scanner, an actual CIS assessment engine, or official CIS Benchmark licensing for the **illustrative** bundled controls.

## Validate installed versions

```powershell
py -3.12 --version
git --version
code --version
aws --version  # optional
```

If `py` is not installed or cannot locate 3.12, install Python 3.12 then re-open the terminal. If the PowerShell activation script is restricted, run the environment's `python.exe` by full path instead; changing the execution policy is not required.

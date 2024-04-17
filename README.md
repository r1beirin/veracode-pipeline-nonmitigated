# Veracode Pipeline Non Mitigated
This script will discard "approved mitigations" from Veracode Plataform and will create a baseline to a Pipeline Scan.

# Usage
Usage: `python main.py -an $application_name -rf results.json -of baseline.json -vid $veracodeID -vkey $veracodeKEY`

Arg `-rf` it's name of results.json from a pipeline scan to matched findings. So it's important create a results.json.

Arg `-of` it's name of baseline that will be created.

# Info
For the script to work, you need to download the following library: `veracode_api_signing` using `pip install veracode-api-signing`.

# Important Notes
This script it's a modified script from [veracode-pipeline-mitigation](https://github.com/tjarrettveracode/veracode-pipeline-mitigation). So, thanks Tim Jarret, Ricardo Pereira, Jon Janegod and Nick Barham.

We perform a naïve match between the mitigated findings and the pipeline findings based on CWE ID, source file and line number value. There is some "slop" built into the match (checking a range in the pipeline finding around the original mitigated finding); you can adjust the constant `LINE_NUMBER_SLOP` to get a more or less precise match.

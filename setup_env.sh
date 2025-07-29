#! /bin/bash
set -e ## Halt on errors

## Activate the conda base environment

if [[ -d "${HOME}/miniconda3/" ]]
then
source ${HOME}/miniconda3/etc/profile.d/conda.sh
elif [[ "${HOME}/miniforge3/" ]]
then
source ${HOME}/miniforge3/etc/profile.d/conda.sh
fi

RAMDISK=NO

echo "Ramdisk creation is set to $RAMDISK"

if [[ "$OSTYPE" == "darwin"* ]]; then
  echo "Running on macOS"
  ENV_NAME="conda_env_osx-64"
  export CONDA_SUBDIR=osx-64 ##  ## Enables creation of a Rosetta 2 emulated intel x86-64 environment on arm64
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
  echo "Running on Linux"
  ENV_NAME="conda_env_linux-64"
  export CONDA_SUBDIR=linux-64
fi

## Setup a ramdisk for the environment. 
if [[ $RAMDISK == "YES" && "$OSTYPE" == "linux-gnu"* ]]; then
  ENV_DIR="/dev/shm/$(whoami)/tmp$(pwd)"  
  mkdir -p "$ENV_DIR"
  echo "Made folder on ramdisk for conda environment:${ENV_DIR}"
  ln -s "$ENV_DIR" ./${ENV_NAME}
  
  elif [[ $RAMDISK == "YES" && "$OSTYPE" == "darwin"* ]]; then
  diskutil erasevolume APFS RAM_Disk_5GiB $(hdiutil attach -nomount ram://10485760) ## See https://www.dr-lex.be/info-stuff/bytecalc.html
  ENV_DIR="/Volumes/RAM_Disk_5GiB/$(whoami)/tmp$(pwd)"
  mkdir -p "$ENV_DIR"
  echo "Made folder on ramdisk for conda environment:${ENV_DIR}"
  ln -s "$ENV_DIR" ./${ENV_NAME}
fi

## Create a local env
conda create -y -p ./${ENV_NAME} 'python=3.13'
conda activate ./${ENV_NAME}

## Add all the conda installable executable dependencies here
conda install -y -c conda-forge pip 

## Export the environment - see https://stackoverflow.com/questions/49174185/export-conda-environment-without-prefix-variable-which-shows-local-path-to-execu
conda env export > conda_env.yaml
conda env export --from-history > conda_env.from-history.yaml

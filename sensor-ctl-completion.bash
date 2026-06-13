#!/usr/bin/env bash

_sensor_ctl_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    # Path to the sensor-ctl.sh script
    # We try to find it relative to the current working directory
    local script="./sensor-ctl.sh"
    if [ ! -f "$script" ]; then
        return 0
    fi

    # Top-level commands
    if [[ ${COMP_CWORD} -eq 1 ]]; then
        opts=$($script __complete commands)
        COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
        return 0
    fi

    local command="${COMP_WORDS[1]}"

    case "${command}" in
        start)
            # If we are at the 3rd word (after name), suggest types
            if [[ ${COMP_CWORD} -eq 3 ]]; then
                opts=$($script __complete types)
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            fi
            ;;
        stop|logs|exec|shell)
            # Suggest running sandboxes
            if [[ ${COMP_CWORD} -eq 2 ]]; then
                opts=$($script __complete running)
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            fi
            ;;
    esac

    return 0
}

complete -F _sensor_ctl_completion sensor-ctl.sh
complete -F _sensor_ctl_completion ./sensor-ctl.sh

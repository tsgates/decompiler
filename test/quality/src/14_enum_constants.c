/* Test 14: Enum-like constants and state machines */

typedef enum { STATE_IDLE, STATE_RUNNING, STATE_PAUSED, STATE_STOPPED } State;
typedef enum { CMD_START, CMD_PAUSE, CMD_RESUME, CMD_STOP, CMD_RESET } Command;

State process_command(State current, Command cmd) {
    switch (current) {
    case STATE_IDLE:
        if (cmd == CMD_START) return STATE_RUNNING;
        if (cmd == CMD_RESET) return STATE_IDLE;
        break;
    case STATE_RUNNING:
        if (cmd == CMD_PAUSE) return STATE_PAUSED;
        if (cmd == CMD_STOP) return STATE_STOPPED;
        break;
    case STATE_PAUSED:
        if (cmd == CMD_RESUME) return STATE_RUNNING;
        if (cmd == CMD_STOP) return STATE_STOPPED;
        break;
    case STATE_STOPPED:
        if (cmd == CMD_RESET) return STATE_IDLE;
        break;
    }
    return current;
}

int count_transitions(Command *cmds, int n) {
    State state = STATE_IDLE;
    int transitions = 0;
    for (int i = 0; i < n; i++) {
        State next = process_command(state, cmds[i]);
        if (next != state) transitions++;
        state = next;
    }
    return transitions;
}

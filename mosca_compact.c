#include <stdio.h>
#include <windows.h>

void setup_console() {
    // Set UTF-8 code page so box drawing characters and symbols (█, ✔, ⚠) render properly
    SetConsoleOutputCP(CP_UTF8);

    // Enable Virtual Terminal Processing for ANSI color escape codes
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        if (GetConsoleMode(hOut, &dwMode)) {
            dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            SetConsoleMode(hOut, dwMode);
        }
    }
}

int main() {
    setup_console();

    // ANSI Color Escape Sequences
    const char *CYAN_BOLD   = "\033[1;36m";
    const char *WHITE_BOLD  = "\033[1;37m";
    const char *RED_BOLD    = "\033[1;31m";
    const char *GREEN_BOLD  = "\033[1;32m";
    const char *YELLOW_BOLD = "\033[1;33m";
    const char *ORANGE_BOLD = "\033[38;5;208m";
    const char *PURPLE_BOLD = "\033[1;35m";
    const char *RESET       = "\033[0m";

    printf("\n");
    // Title
    printf("         %sMOSCA QUANTUM RISK ASSESSMENT — CENTRAL HORIZON [2038 (Z = 12 yrs)]%s\n", CYAN_BOLD, RESET);

    // Box Top Border
    printf("%s┌────────────────┬─────────────┬──────────────┬───────────────────────────────────────┐%s\n", CYAN_BOLD, RESET);
    
    // Headers
    printf("%s│%s %s%-14s%s %s│%s %s%-11s%s %s│%s %s%-12s%s %s│%s %s%-37s%s %s│%s\n",
           CYAN_BOLD, RESET, WHITE_BOLD, "Risk Level", RESET,
           CYAN_BOLD, RESET, WHITE_BOLD, "Asset Count", RESET,
           CYAN_BOLD, RESET, WHITE_BOLD, "SNDL Exposed", RESET,
           CYAN_BOLD, RESET, WHITE_BOLD, "NIST PQC Replacement Target", RESET,
           CYAN_BOLD, RESET);

    // Divider
    printf("%s├────────────────┼─────────────┼──────────────┼───────────────────────────────────────┤%s\n", CYAN_BOLD, RESET);

    // Row 1: CRITICAL
    printf("%s│%s %s█ CRITICAL    %s %s│%s      %s3%s      %s│%s      %s3%s       %s│%s %sML-KEM-768 / ML-DSA-65 (FIPS 203/204)%s %s│%s\n",
           CYAN_BOLD, RESET, RED_BOLD, RESET,
           CYAN_BOLD, RESET, WHITE_BOLD, RESET,
           CYAN_BOLD, RESET, RED_BOLD, RESET,
           CYAN_BOLD, RESET, WHITE_BOLD, RESET,
           CYAN_BOLD, RESET);

    // Row 2: HIGH
    printf("%s│%s %s█ HIGH        %s %s│%s      %s7%s      %s│%s      %s0%s       %s│%s %s%-37s%s %s│%s\n",
           CYAN_BOLD, RESET, ORANGE_BOLD, RESET,
           CYAN_BOLD, RESET, WHITE_BOLD, RESET,
           CYAN_BOLD, RESET, GREEN_BOLD, RESET,
           CYAN_BOLD, RESET, WHITE_BOLD, "ML-KEM-768 / ML-DSA-65", RESET,
           CYAN_BOLD, RESET);

    // Row 3: MEDIUM
    printf("%s│%s %s█ MEDIUM      %s %s│%s    %s214%s      %s│%s     %s57%s       %s│%s %s%-37s%s %s│%s\n",
           CYAN_BOLD, RESET, YELLOW_BOLD, RESET,
           CYAN_BOLD, RESET, WHITE_BOLD, RESET,
           CYAN_BOLD, RESET, RED_BOLD, RESET,
           CYAN_BOLD, RESET, WHITE_BOLD, "ML-KEM-768 / ML-DSA-65", RESET,
           CYAN_BOLD, RESET);

    // Row 4: QUANTUM-SAFE
    printf("%s│%s %s✔ QUANTUM-SAFE%s %s│%s    %s196%s      %s│%s      %s0%s       %s│%s %s%-37s%s %s│%s\n",
           CYAN_BOLD, RESET, GREEN_BOLD, RESET,
           CYAN_BOLD, RESET, WHITE_BOLD, RESET,
           CYAN_BOLD, RESET, GREEN_BOLD, RESET,
           CYAN_BOLD, RESET, WHITE_BOLD, "None (Quantum Safe)", RESET,
           CYAN_BOLD, RESET);

    // Box Bottom Border
    printf("%s└────────────────┴─────────────┴──────────────┴───────────────────────────────────────┘%s\n", CYAN_BOLD, RESET);

    // Alert
    printf(" %s⚠%s %sCRITICAL ALERT:%s %s10 asset(s) fail Mosca's inequality in the central scenario.%s\n\n",
           YELLOW_BOLD, RESET, RED_BOLD, RESET, RED_BOLD, RESET);

    return 0;
}

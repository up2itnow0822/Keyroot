export type PageSignal = 'expected' | 'destination-changed' | 'unexpected-mfa' | 'passkey' | 'privilege-instruction' | 'unknown';
export function assessDrift(signal: PageSignal): 'continue' | 'pause-guided' {
    return signal === 'expected' ? 'continue' : 'pause-guided';
}

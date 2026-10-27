import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { createServer, type Server } from 'node:net';
/** An exclusive kernel listener; never automatically removes a predecessor's stale socket. */
export class BootFence {
    readonly bootId = randomUUID();
    private constructor(private readonly server: Server) {
    }
    static async acquire(socketPath: string): Promise<BootFence> {
        if (!isAbsolute(socketPath) || socketPath.length > 100)
            throw new Error('Use a short absolute local singleton socket path');
        if (existsSync(socketPath))
            throw new Error('Singleton socket exists; operator predecessor reconciliation required');
        const server = createServer(socket => socket.destroy());
        await new Promise<void>((resolve, reject) => {
            server.once('error', reject);
            server.listen({ path: socketPath, exclusive: true }, () => {
                server.removeListener('error', reject);
                resolve();
            });
        });
        return new BootFence(server);
    }
    async release(): Promise<void> {
        await new Promise<void>((resolve, reject) => this.server.close(error => error ? reject(error) : resolve()));
    }
}

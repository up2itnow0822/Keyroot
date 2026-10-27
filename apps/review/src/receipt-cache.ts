export type Receipt = { kind: string; outcome: string; limitationCodes: string[]; consumerId?: string; journalInterpretation?: { kind: string; outcome: string } };
export type ReceiptCache = Record<string, Receipt[]>;
export function putReceipts(cache: ReceiptCache, operationId: string, receipts: Receipt[]): ReceiptCache { return { ...cache, [operationId]: receipts }; }
export function receiptsFor(cache: ReceiptCache, operationId: string): Receipt[] { return cache[operationId] ?? []; }

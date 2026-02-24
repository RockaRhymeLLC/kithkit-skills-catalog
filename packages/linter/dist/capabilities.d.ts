/**
 * Kithkit — Well-Known Capability Namespace
 *
 * Framework-agnostic capabilities describing what an agent CAN DO.
 * Flat list for v1, extensible — unknown capabilities warn, not error.
 */
export interface CapabilityDef {
    name: string;
    description: string;
}
export declare const WELL_KNOWN_CAPABILITIES: CapabilityDef[];
export declare const CAPABILITY_NAMES: Set<string>;
/**
 * Check if a capability is in the well-known list.
 */
export declare function isKnownCapability(name: string): boolean;
/**
 * Get the description for a well-known capability.
 */
export declare function getCapabilityDescription(name: string): string | undefined;

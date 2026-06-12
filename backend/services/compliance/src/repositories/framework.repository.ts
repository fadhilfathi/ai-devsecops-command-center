import type { ComplianceFramework, UUID } from '@aicc/shared';

export interface FrameworkInfo {
  id: ComplianceFramework;
  name: string;
  version: string;
  description: string;
  controlCount: number; // metadata only
}

export interface FrameworkRepository {
  list(tenantId: UUID): Promise<FrameworkInfo[]>;
  supported(): FrameworkInfo[];
}

const SUPPORTED: FrameworkInfo[] = [
  { id: 'cis_v8', name: 'CIS Critical Security Controls', version: 'v8', description: 'Center for Internet Security — Critical Security Controls v8', controlCount: 153 },
  { id: 'nist_800_53', name: 'NIST 800-53', version: 'Rev. 5', description: 'Security and Privacy Controls for Information Systems and Organizations', controlCount: 1189 },
  { id: 'soc2', name: 'SOC 2', version: '2017 TSC', description: 'AICPA Trust Services Criteria', controlCount: 64 },
  { id: 'iso_27001', name: 'ISO/IEC 27001', version: '2022', description: 'Information security management systems requirements', controlCount: 93 },
];

export function buildFrameworkRepository(): FrameworkRepository {
  return {
    async list(_tenantId) {
      return SUPPORTED;
    },
    supported() {
      return SUPPORTED;
    },
  };
}

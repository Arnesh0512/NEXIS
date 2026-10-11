import { abcd_hashDatasetSha256 } from '../compliance/integrity_verifier';


export function ts_validate_subject_identity(subject: string): boolean {
  return Boolean(subject);
}

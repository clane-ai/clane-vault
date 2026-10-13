import { vendor, vendorUrl } from "@/brand";

/** The small "by Clane AI Labs" credit; a link when VITE_VENDOR_URL is set. */
export function VendorCredit({ className }: { className?: string }) {
  return vendorUrl
    ? <a href={vendorUrl} target="_blank" rel="noopener noreferrer" className={className}>by {vendor}</a>
    : <span className={className}>by {vendor}</span>;
}

export type Finding = {rule_id:string;name:string;category:string;severity:string;explanation:string;evidence:string[];recommendation:string;source:string;limitations:string}
export type Scan = {id:number;original_url:string;normalized_url:string;hostname:string;registered_domain:string;risk_score:number;risk_level:string;score_reasons:string[];findings:Finding[];created_at:string}
export type Page = {items:Scan[];total:number;page:number;page_size:number}
export type Summary = {total_scans:number;high_risk:number;critical:number;distribution:Record<string,number>;categories:{name:string;count:number}[];recent:Scan[]}

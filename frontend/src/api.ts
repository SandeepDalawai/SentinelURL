import type {Page, Scan, Summary} from './types'

const base = (import.meta as any).env?.VITE_API_URL || 'http://127.0.0.1:8000/api/v1'
async function request<T>(path:string, options?:RequestInit):Promise<T>{
  const response=await fetch(`${base}${path}`,options)
  if(!response.ok){let message=`Request failed (${response.status})`;try{const data=await response.json();const detail=data.detail;message=typeof detail==='string'?detail:Array.isArray(detail)?detail.map((item:any)=>item.msg||'Invalid request').join('; '):message}catch{}throw new Error(message)}
  return response.json()
}
export const api={
  health:()=>request<{status:string}>('/health'),
  scan:(url:string)=>request<Scan>('/scans',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})}),
  history:(search='',severity='',page=1,startDate='',endDate='',sortBy='created_at',sortOrder='desc')=>{const params=new URLSearchParams({search,severity,sort_by:sortBy,sort_order:sortOrder,page:String(page),page_size:'50'});if(startDate)params.set('start_date',startDate);if(endDate)params.set('end_date',endDate);return request<Page>(`/scans?${params.toString()}`)},
  get:(id:number)=>request<Scan>(`/scans/${id}`),
  remove:(id:number)=>request(`/scans/${id}`,{method:'DELETE'}),
  summary:()=>request<Summary>('/analytics/summary'),
  trends:()=>request<{items:{date:string;scans:number}[]}>('/analytics/trends'),
  bulk:async(file:File)=>{const form=new FormData();form.append('file',file);return request<{items:(Scan|{row:number;url:string;error:string})[];total:number;successful:number;failed:number}>('/scans/bulk',{method:'POST',body:form})},
  exportUrl:`${base}/reports/export.csv`
}

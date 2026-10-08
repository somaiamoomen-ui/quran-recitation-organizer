import { createClient } from "npm:@supabase/supabase-js@2";
import webpush from "npm:web-push@3.6.7";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const BUCKET = "recitation-recordings";
const REJECTION_MESSAGE = `نأسف لعدم إمكانية انضمامك الآن لمجموعات الحفظ الخاصة بأكاديمية سطور الهدى

لكن نبشرك بإمكانية الانضمام لمقرأة (سطور الهدى) الخاصة بتصحيح التلاوة
من الرابط التالي:
https://chat.whatsapp.com/HfV64cNgmhtCVLmG5vFrgf?s=cl&p=a&ilr=4&iam=1
وفى انتظارك إن شاء الله فى جروبات أخرى بعد إجادة احكام التجويد

نسأل الله لك التوفيق والسداد`;

const json=(body:unknown,status=200)=>new Response(JSON.stringify(body),{status,headers:{...corsHeaders,"Content-Type":"application/json; charset=utf-8"}});
const secretKeys=JSON.parse(Deno.env.get("SUPABASE_SECRET_KEYS")||"{}");
const db=createClient(Deno.env.get("SUPABASE_URL")!,secretKeys.default||Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

async function sha256(text:string){const data=new TextEncoder().encode(text);const hash=await crypto.subtle.digest("SHA-256",data);return Array.from(new Uint8Array(hash)).map(b=>b.toString(16).padStart(2,"0")).join("")}
const companionTokenSecret=secretKeys.default||Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
function companionTokenEncode(payload:string){return btoa(payload).replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=+$/,"")}
async function makeCompanionToken(registrationId:string,trackId:string){
 const exp=Date.now()+30*60*1000,payload=JSON.stringify({r:registrationId,t:trackId,e:exp}),encoded=companionTokenEncode(payload),sig=await sha256(companionTokenSecret+"|"+encoded);
 return encoded+"."+sig;
}
async function verifyCompanionToken(token:string,registrationId:string,trackId:string){
 const parts=String(token||"").split(".");if(parts.length!==2)return false;
 try{
  const encoded=parts[0],payload=JSON.parse(atob(encoded.replace(/-/g,"+").replace(/_/g,"/"))),expected=await sha256(companionTokenSecret+"|"+encoded);
  return payload?.r===registrationId&&payload?.t===trackId&&Number(payload?.e)>Date.now()&&parts[1]===expected;
 }catch{return false}
}
async function checkPassword(role:"teacher"|"admin",password:string){
 const {data,error}=await db.from("app_settings").select("teacher_password_hash,admin_password_hash").eq("id",1).single();
 if(error||!data)return false;
 return (await sha256(password))===(role==="teacher"?data.teacher_password_hash:data.admin_password_hash);
}
async function requireRole(body:any,role:"teacher"|"admin"){return !!body?.password&&await checkPassword(role,String(body.password))}
async function audit(action:string,trackId:string|null,details:any){try{await db.from("admin_audit_logs").insert({action,track_id:trackId,details,created_at:new Date().toISOString()})}catch(e){console.error("audit log failed",e)}}
async function checkPendingAlert(trackId:string){
 const {data:track,error:te}=await db.from("tracks").select("id,name,pending_alert_active").eq("id",trackId).single();
 if(te||!track)return;
 const {count,error:ce}=await db.from("registrations").select("id",{count:"exact",head:true}).eq("track_id",trackId).eq("latest_status","pending");
 if(ce)return;
 const pending=count||0;
 if(pending<50){if(track.pending_alert_active)await db.from("tracks").update({pending_alert_active:false,updated_at:new Date().toISOString()}).eq("id",trackId);return;}
 if(track.pending_alert_active)return;
 const {data:subs,error:se}=await db.from("teacher_push_subscriptions").select("id,endpoint,p256dh,auth,enabled").eq("track_id",trackId).eq("enabled",true);if(se)throw se;
 const {data:settings,error:ae}=await db.from("app_settings").select("vapid_public_key,vapid_private_key,vapid_subject").eq("id",1).single();if(ae||!settings?.vapid_public_key||!settings?.vapid_private_key||!settings?.vapid_subject)return;
 webpush.setVapidDetails(settings.vapid_subject,settings.vapid_public_key,settings.vapid_private_key);let sent=0;
 for(const s of subs||[]){try{await webpush.sendNotification({endpoint:s.endpoint,keys:{p256dh:s.p256dh,auth:s.auth}},JSON.stringify({title:"أكاديمية سطور الهدى",body:"يوجد "+pending+" تسجيلًا معلقًا في مسار "+track.name+".",tag:"pending-"+trackId,url:"./"}));sent++;}catch(e:any){const code=Number(e?.statusCode||0);if(code===404||code===410)await db.from("teacher_push_subscriptions").update({enabled:false,updated_at:new Date().toISOString()}).eq("id",s.id);else console.error("push send failed",e);}}
 if(sent>0)await db.from("tracks").update({pending_alert_active:true,updated_at:new Date().toISOString()}).eq("id",trackId).eq("pending_alert_active",false);
}
function normalizeName(name:string){return name.trim().replace(/\s+/g," ").split(" ").map((part:string)=>part.replace(/^[اأإآ]/u,"ا").replace(/ى$/u,"ي").replace(/ة$/u,"ه")).join(" ")}
function canonicalName(name:string){
 return normalizeName(String(name||"")).toLocaleLowerCase("ar-EG").replace(/\s+/g,"");
}
function canonicalParts(name:string){
 return normalizeName(String(name||"")).toLocaleLowerCase("ar-EG").split(" ").filter(Boolean).map(part=>part.replace(/\s+/g,""));
}
function partCanMatchEntered(enteredPart:string,storedParts:string[],startIndex:number){
 const target=String(enteredPart||"");
 if(!target)return [];
 let joined="";
 const ends:number[]=[];
 for(let i=startIndex;i<storedParts.length;i++){
   joined+=storedParts[i];
   ends.push(i);
   if(joined===target)return ends;
   if(joined.length>target.length)break;
 }
 return [];
}
function flexibleNamePartsMatch(entered:string,stored:string){
 const a=canonicalParts(entered),b=canonicalParts(stored);
 if(a.length<2||b.length<2)return false;
 // الاسم الثنائي لا يطابق اسمًا ثلاثيًا أو رباعيًا؛ المطابقة الجزئية مسموحة من 3 أسماء فأكثر.
 if((a.length===2)!==(b.length===2))return false;
 if(a[0]!==b[0]){
  const enteredCanonical=a.join("");
  const storedCanonical=b.join("");
  if(enteredCanonical.length>=2&&storedCanonical.startsWith(enteredCanonical))return true;
  return false;
 }
 const secondEnds=partCanMatchEntered(a[1],b,1);
 if(!secondEnds.length){
  const enteredCanonical=a.join("");
  const storedCanonical=b.join("");
  if(enteredCanonical.length>=2&&storedCanonical.startsWith(enteredCanonical))return true;
  return false;
 }
 for(const secondEnd of secondEnds){
   let ai=2;
   let searchFrom=secondEnd+1;
   let ok=true;
   while(ai<a.length){
     let matched=false;
     for(let bi=searchFrom;bi<b.length;bi++){
       const ends=partCanMatchEntered(a[ai],b,bi);
       if(ends.length){
         matched=true;
         searchFrom=ends[ends.length-1]+1;
         break;
       }
     }
     if(!matched){ok=false;break}
     ai++;
   }
   if(ok)return true;
 }
 return false;
}
function literalNameParts(name:string){
 return String(name||"").trim().replace(/\\s+/g," ").toLocaleLowerCase("ar-EG").split(" ").filter(Boolean);
}
function literalNamePartsMatch(entered:string,stored:string){
 const a=literalNameParts(entered),b=literalNameParts(stored);
 if(a.length<2||b.length<2)return false;
 // الاسم الثنائي لا يطابق اسمًا ثلاثيًا أو رباعيًا؛ من 3 أسماء فأكثر نسمح بالمطابقة على نفس البداية.
 if((a.length===2)!==(b.length===2))return false;
 if(a[0]!==b[0]||a[1]!==b[1])return false;
 let ai=2,searchFrom=2;
 while(ai<a.length){
  let matched=false;
  for(let bi=searchFrom;bi<b.length;bi++){
   if(a[ai]===b[bi]){
    matched=true;
    searchFrom=bi+1;
    break;
   }
  }
  if(!matched)return false;
  ai++;
 }
 return true;
}
async function findRetryNameCandidates(name:string,trackId:string){
 const entered=canonicalParts(name);
 if(entered.length<2)return [];
 const {data,error}=await db.from("registrations").select("id,student_name,student_name_normalized,latest_status,updated_at,track_id").eq("track_id",trackId).eq("latest_status","retry").order("updated_at",{ascending:false});
 if(error)throw error;
 return (data||[]).filter((row:any)=>{
  const stored=canonicalParts(row.student_name||row.student_name_normalized||"");
  if(stored.length<=entered.length)return false;
  for(let i=0;i<entered.length;i++)if(stored[i]!==entered[i])return false;
  return true;
 });
}
async function findRegistrationsByFlexibleName(name:string,trackId:string){
 const key=canonicalName(name);
 if(!key)return [];
 const {data,error}=await db.from("registrations")
   .select("id,student_name,student_name_normalized,result_aliases,latest_status,updated_at,companion_group_link_used_at,companion_group_link_use_count,track_id,tracks(name,whatsapp_link,primary_group_link)")
   .eq("track_id",trackId)
   .order("updated_at",{ascending:false});
 if(error)throw error;
 const rows=data||[];
 const literal=rows.filter((row:any)=>literalNamePartsMatch(name,row.student_name||row.student_name_normalized||""));
 if(literal.length===1)return literal;
 const exact=rows.filter((row:any)=>canonicalName(row.student_name||row.student_name_normalized||"")===key);
 if(exact.length)return exact;
 const flexible=rows.filter((row:any)=>flexibleNamePartsMatch(name,row.student_name||row.student_name_normalized||""));
 return flexible.length===1?flexible:[];
}
async function findFlexibleResultCandidates(name:string,trackId:string){
 const key=canonicalName(name);
 if(!key)return [];
 const {data,error}=await db.from("registrations")
   .select("id,student_name,student_name_normalized,latest_status,updated_at,companion_group_link_used_at,companion_group_link_use_count,track_id,tracks(name,whatsapp_link,primary_group_link)")
   .eq("track_id",trackId)
   .order("updated_at",{ascending:false});
 if(error)throw error;
 const rows=data||[];
 const literal=rows.filter((row:any)=>literalNamePartsMatch(name,row.student_name||row.student_name_normalized||""));
 if(literal.length)return literal;
 const exact=rows.filter((row:any)=>canonicalName(row.student_name||row.student_name_normalized||"")===key);
 if(exact.length)return exact;
 return rows.filter((row:any)=>flexibleNamePartsMatch(name,row.student_name||row.student_name_normalized||""));
}
function resultAliasMatches(name:string,row:any){
 const key=canonicalName(name);
 const aliases=Array.isArray(row?.result_aliases)?row.result_aliases:[];
 return !!key&&aliases.some((alias:string)=>canonicalName(alias)===key);
}
function validName(name:string){return normalizeName(name).length>0}
async function getOpenTracks(){const {data,error}=await db.from("tracks").select("id,name,whatsapp_link,is_open,sort_order").eq("is_open",true).order("sort_order");if(error)throw error;return data||[]}
async function getResult(name:string,trackId:string){
 const matches=await findFlexibleResultCandidates(name,trackId);
 const evaluatedMatches=matches.filter((row:any)=>row.latest_status==="accepted"||row.latest_status==="rejected"||row.latest_status==="retry");
 if(evaluatedMatches.length)matches.splice(0,matches.length,...evaluatedMatches.slice(0,1));
 else {
  const pendingMatch=matches.find((row:any)=>row.latest_status==="pending");
  if(pendingMatch)matches.splice(0,matches.length,pendingMatch);
  else matches.splice(0,matches.length);
 }
 if(!matches.length){
  const key=canonicalName(name);
  const {data:otherRows,error:otherError}=await db.from("registrations").select("id,student_name,student_name_normalized,track_id,tracks(name)").neq("track_id",trackId);
  if(otherError)throw otherError;
  const otherMatches=(otherRows||[]).filter((row:any)=>canonicalName(row.student_name||row.student_name_normalized||"")===key||flexibleNamePartsMatch(name,row.student_name||row.student_name_normalized||""));
  const uniqueTrackIds=[...new Set(otherMatches.map((row:any)=>String(row.track_id||"")).filter(Boolean))];
  if(uniqueTrackIds.length===1){
    const row=otherMatches.find((x:any)=>String(x.track_id||"")===uniqueTrackIds[0]);
    const track:any=Array.isArray(row?.tracks)?row.tracks[0]:row?.tracks;
    return {found:false,wrongTrack:true,correctTrackId:uniqueTrackIds[0],correctTrackName:String(track?.name||"")};
  }
  if(uniqueTrackIds.length>1)return {found:false,wrongTrack:true};
  return {found:false};
}
 if(matches.length>1){
  const parts=canonicalParts(name);
  const message=parts.length<=2?"برجاء كتابة الاسم ثلاثيًا للوصول إلى النتيجة.":"برجاء كتابة الاسم بصورة أكثر تحديدًا للوصول إلى النتيجة.";
  return {found:false,ambiguous:true,message};
 }
 const row=matches[0];
 const track:any=Array.isArray(row.tracks)?row.tracks[0]:row.tracks;
 let retryNote="";
 if(row.latest_status==="retry"){
  const {data:ev,error:ee}=await db.from("evaluations").select("note,evaluated_at").eq("registration_id",row.id).eq("status","retry").order("evaluated_at",{ascending:false}).limit(1).maybeSingle();
  if(ee)throw ee;
  retryNote=String(ev?.note||"");
 }
 const companionUseCount=Number(row.companion_group_link_use_count)||0;return {found:true,registrationId:row.id,studentName:row.student_name,trackId:row.track_id,trackName:track?.name||"",status:row.latest_status,whatsappLink:row.latest_status==="accepted"?(track?.whatsapp_link||""):"",companionGroupLinkUseCount:companionUseCount,companionGroupLinkUsed:companionUseCount>=2,rejectionMessage:row.latest_status==="rejected"?REJECTION_MESSAGE:"",retryNote};
}
Deno.serve(async(req)=>{
 if(req.method==="OPTIONS")return new Response("ok",{headers:corsHeaders});
 try{
  const url=new URL(req.url),action=url.searchParams.get("action")||"";
  if(action==="tracks"){const tracks=await getOpenTracks();const {data:settings,error}=await db.from("app_settings").select("student_evaluation_text").eq("id",1).single();if(error)throw error;return json({tracks,evaluationText:String(settings?.student_evaluation_text||"")});}
  if(action==="teacher-options"){
   const body=await req.json();
   if(!(await requireRole(body,"teacher")))return json({error:"كلمة مرور المعلمة غير صحيحة."},401);
   const {data,error}=await db.from("tracks").select("id,name,teacher1_name,teacher2_name,teacher3_name,teacher4_name").order("sort_order");
   if(error)throw error;
   return json({tracks:(data||[]).map((t:any)=>({...t,teachers:[t.teacher1_name,t.teacher2_name,t.teacher3_name,t.teacher4_name].filter((x:string)=>String(x||"").trim())}))});
  }
  if(action==="push-config"){
   const {data,error}=await db.from("app_settings").select("vapid_public_key").eq("id",1).single();
   if(error||!data?.vapid_public_key)return json({error:"إعداد الإشعارات غير مكتمل حاليًا."},503);
   return json({publicKey:data.vapid_public_key});
  }
  if(action==="subscribe-teacher-push"){
   const body=await req.json();
   if(!(await requireRole(body,"teacher")))return json({error:"كلمة مرور المعلمة غير صحيحة."},401);
   const trackId=String(body.trackId||""),teacherName=normalizeName(String(body.teacherName||""));
   const sub=body.subscription||{};
   if(!trackId||!validName(teacherName)||!sub.endpoint||!sub.keys?.p256dh||!sub.keys?.auth)return json({error:"بيانات الإشعارات غير مكتملة."},400);
   const {data:track,error:te}=await db.from("tracks").select("id,teacher1_name,teacher2_name,teacher3_name,teacher4_name").eq("id",trackId).single();
   if(te||!track)return json({error:"المسار غير موجود."},404);
   const allowed=[track.teacher1_name,track.teacher2_name,track.teacher3_name,track.teacher4_name].filter(Boolean).map((x:string)=>normalizeName(x).toLocaleLowerCase("ar-EG"));
   if(!allowed.includes(teacherName.toLocaleLowerCase("ar-EG")))return json({error:"هذه المعلمة ليست مسؤولة عن هذا المسار."},403);
   const {error}=await db.from("teacher_push_subscriptions").upsert({track_id:trackId,teacher_name:teacherName,endpoint:String(sub.endpoint),p256dh:String(sub.keys.p256dh),auth:String(sub.keys.auth),enabled:true,updated_at:new Date().toISOString()},{onConflict:"endpoint"});
   if(error)throw error;
   return json({ok:true});
  }
  if(action==="all-tracks"){const body=await req.json();if(!(await requireRole(body,"teacher")))return json({error:"كلمة مرور المعلمة غير صحيحة."},401);const {data,error}=await db.from("tracks").select("id,name").order("sort_order");if(error)throw error;return json({tracks:data||[]})}
  if(action==="companion-start"){
   const body=await req.json(),registrationId=String(body.registrationId||""),trackId=String(body.trackId||"");
   if(!registrationId||!trackId)return json({error:"الرابط غير صالح."},400);
   const consumed=await db.rpc("consume_companion_group_link",{p_registration_id:registrationId,p_track_id:trackId});
   if(consumed.error)throw consumed.error;
   const row=consumed.data?.[0];
   if(row)return json({ok:true,whatsappLink:String(row.whatsapp_link||""),useCount:Number(row.use_count)||0,remainingUses:Math.max(0,2-(Number(row.use_count)||0))});
   const {data:check,error:ce}=await db.from("registrations").select("id,latest_status,companion_group_link_use_count,tracks(whatsapp_link)").eq("id",registrationId).eq("track_id",trackId).maybeSingle();
   if(ce)throw ce;
   if(!check||check.latest_status!=="accepted")return json({error:"هذا الرابط متاح للطالبات المقبولات فقط."},403);
   const checkTrack:any=Array.isArray(check.tracks)?check.tracks[0]:check.tracks;
   if(!checkTrack?.whatsapp_link)return json({error:"لم يتم إضافة رابط جروب الرفيقات لهذا المسار بعد."},404);
   if((Number(check.companion_group_link_use_count)||0)>=2)return json({error:"تم استخدام رابط جروب الرفيقات مرتين، لذلك لم يعد الرابط متاحًا من الموقع."},409);
   return json({error:"تعذر تسجيل محاولة فتح الرابط، برجاء المحاولة مرة أخرى."},409);
  }
  if(action==="companion-confirm"){
   const body=await req.json(),registrationId=String(body.registrationId||""),trackId=String(body.trackId||""),token=String(body.token||"");
   if(!registrationId||!trackId||!(await verifyCompanionToken(token,registrationId,trackId)))return json({error:"محاولة التحقق غير صالحة أو انتهت مدتها."},400);
   const {data:row,error}=await db.from("registrations").select("id,track_id,latest_status,companion_group_link_used_at,companion_group_link_use_count").eq("id",registrationId).eq("track_id",trackId).maybeSingle();
   if(error)throw error;
   if(!row||row.latest_status!=="accepted")return json({error:"هذا الرابط متاح للطالبات المقبولات فقط."},403);
   const usedAt=row.companion_group_link_used_at?new Date(row.companion_group_link_used_at).getTime():0;
   const count=Number(row.companion_group_link_use_count)||0;
   const retryAllowed=count<1||(usedAt>0&&Date.now()-usedAt<15*60*1000);
   if(!retryAllowed)return json({ok:true,alreadyConfirmed:true});
   if(count<1){
    const now=new Date().toISOString();
    const updated=await db.from("registrations").update({companion_group_link_used_at:now,companion_group_link_use_count:1}).eq("id",row.id).eq("latest_status","accepted").or("companion_group_link_use_count.is.null,companion_group_link_use_count.lt.1").select("id").maybeSingle();
    if(updated.error)throw updated.error;
    if(!updated.data){
     const {data:check}=await db.from("registrations").select("companion_group_link_used_at,companion_group_link_use_count").eq("id",row.id).maybeSingle();
     const checkAt=check?.companion_group_link_used_at?new Date(check.companion_group_link_used_at).getTime():0;
     const checkCount=Number(check?.companion_group_link_use_count)||0;
     if(checkCount<1||(checkAt>0&&Date.now()-checkAt<15*60*1000))return json({ok:true,alreadyConfirmed:true});
     return json({error:"تم استخدام رابط جروب الرفيقات من قبل، ولا يمكن استخدامه مرة أخرى من الموقع."},409);
    }
   }
   return json({ok:true});
  }
  if(action==="companion-redirect"){
   const registrationId=String(url.searchParams.get("registrationId")||""),trackId=String(url.searchParams.get("trackId")||"");
   if(!registrationId||!trackId)return json({error:"الرابط غير صالح."},400);
   const {data:row,error}=await db.from("registrations").select("id,track_id,latest_status,companion_group_link_used_at,companion_group_link_use_count,tracks(whatsapp_link)").eq("id",registrationId).eq("track_id",trackId).maybeSingle();
   if(error)throw error;
   if(!row||row.latest_status!=="accepted")return json({error:"هذا الرابط متاح للطالبات المقبولات فقط."},403);
   const track:any=Array.isArray(row.tracks)?row.tracks[0]:row.tracks,link=track?.whatsapp_link||"";
   if(!link)return json({error:"لم يتم إضافة رابط جروب الرفيقات لهذا المسار بعد."},404);
   const usedAt=row.companion_group_link_used_at?new Date(row.companion_group_link_used_at).getTime():0;
   const retryAllowed=(Number(row.companion_group_link_use_count)||0)<1||(usedAt>0&&Date.now()-usedAt<15*60*1000);
   if(!retryAllowed)return json({error:"تم استخدام رابط جروب الرفيقات من قبل، ولا يمكن استخدامه مرة أخرى من الموقع."},409);
   return Response.redirect(link,302);
  }
  if(action==="result"){const body=await req.json();const name=String(body.name||"").trim().replace(/\s+/g," "),trackId=String(body.trackId||"");if(!validName(name))return json({error:"برجاء إدخال الاسم."},400);if(!trackId)return json({error:"برجاء اختيار المسار."},400);return json(await getResult(name,trackId))}
  if(action==="register-companion"){
   const body=await req.json(),name=normalizeName(String(body.name||"")),name2=normalizeName(String(body.name2||"")),trackId=String(body.trackId||""),pairNumber=Number(String(body.pairNumber||"")),riwaya=String(body.riwaya||"");
   if(!validName(name)||!validName(name2)||!trackId||!Number.isInteger(pairNumber)||pairNumber<1||!["حفص","قالون"].includes(riwaya))return json({error:"بيانات الرفقة غير مكتملة."},400);
   const n1=name.toLocaleLowerCase("ar-EG"),n2=name2.toLocaleLowerCase("ar-EG");
   if(n1===n2)return json({error:"لا يمكن تسجيل الطالبة مع نفسها."},400);
   const {data:track,error:trackError}=await db.from("tracks").select("id,name").eq("id",trackId).maybeSingle();
   if(trackError)throw trackError;
   if(!track)return json({error:"المسار المختار غير موجود."},400);
   const getAccepted=async(n:string,selectedId?:string)=>{const matches=await findRegistrationsByFlexibleName(n,trackId);const evaluated=matches.filter((row:any)=>row.latest_status==="accepted"||row.latest_status==="rejected"||row.latest_status==="retry");if(selectedId){return evaluated.find((row:any)=>row.id===selectedId&&row.latest_status==="accepted")||null}const accepted=evaluated.filter((row:any)=>row.latest_status==="accepted");if(accepted.length>1)return {ambiguous:true,candidates:accepted.map((row:any)=>({id:row.id,name:row.student_name}))};return accepted[0]||null};
   const a:any=await getAccepted(n1,String(body.student1RegistrationId||"")),b:any=await getAccepted(n2,String(body.student2RegistrationId||""));
   if(a?.ambiguous)return json({error:"وجدنا أكثر من اسم مقبول مشابه، من فضلك اختاري اسم الطالبة الأولى.",code:"ambiguous_student1",candidates:a.candidates},409);
   if(b?.ambiguous)return json({error:"وجدنا أكثر من اسم مقبول مشابه، من فضلك اختاري اسم الطالبة الثانية.",code:"ambiguous_student2",candidates:b.candidates},409);
   if(!a||a.latest_status!=="accepted")return json({error:"الطالبة الأولى غير موجودة ضمن الطالبات المقبولات في المسار المختار."},403);
   if(!b||b.latest_status!=="accepted")return json({error:"الطالبة الثانية غير موجودة ضمن الطالبات المقبولات في المسار المختار."},403);
   const {data:existing,error:pe}=await db.from("companion_pairs").select("id,student1_registration_id,student2_registration_id,pair_number");if(pe)throw pe;
   const samePair=(existing||[]).find((p:any)=>(p.student1_registration_id===a.id&&p.student2_registration_id===b.id)||(p.student1_registration_id===b.id&&p.student2_registration_id===a.id));
   if(samePair){const {data:primaryTrack,error:primaryTrackError}=await db.from("tracks").select("primary_group_link").eq("id",trackId).maybeSingle();if(primaryTrackError)throw primaryTrackError;return json({error:"رفيقتك بالفعل سجلت رفقتكم، وتم تسجيلها بنجاح.",code:"same_pair_already_registered",pairNumber:Number(samePair.pair_number)||pairNumber,student1Name:a.student_name,student2Name:b.student_name,primaryGroupLink:String(primaryTrack?.primary_group_link||"")},409);}
   if((existing||[]).some((p:any)=>p.student1_registration_id===a.id||p.student2_registration_id===a.id||p.student1_registration_id===b.id||p.student2_registration_id===b.id))return json({error:"إحدى الطالبتين مسجلة بالفعل مع رفيقة أخرى."},409);
   const existingIds=[...(existing||[])].flatMap((p:any)=>[p.student1_registration_id,p.student2_registration_id]);
   const {data:existingRegs,error:ere}=existingIds.length?await db.from("registrations").select("id,track_id").in("id",existingIds):{data:[],error:null};
   if(ere)throw ere;
   const trackByReg:Record<string,string>={};for(const r of existingRegs||[])trackByReg[r.id]=r.track_id;
   if((existing||[]).some((p:any)=>trackByReg[p.student1_registration_id]===a.track_id&&Number(p.pair_number)===pairNumber||trackByReg[p.student2_registration_id]===a.track_id&&Number(p.pair_number)===pairNumber))return json({error:"رقم الرفيقة مستخدم بالفعل في هذا المسار، برجاء إدخال رقم آخر."},409);
   const inserted=await db.from("companion_pairs").insert({student1_registration_id:a.id,student2_registration_id:b.id,riwaya,pair_number:pairNumber}).select("id").single();if(inserted.error)throw inserted.error;
   return json({ok:true,pairNumber,student1Name:a.student_name,student2Name:b.student_name,riwaya,primaryGroupLink:(Array.isArray(a.tracks)?a.tracks[0]:a.tracks)?.primary_group_link||""});
  }
  if(action==="use-companion-group-link"){
   const body=await req.json(),name=normalizeName(String(body.name||"")),trackId=String(body.trackId||"");if(!validName(name))return json({error:"برجاء إدخال الاسم."},400);
   if(!trackId)return json({error:"برجاء اختيار المسار."},400);
   const normalized=name.toLocaleLowerCase("ar-EG");
   const {data:row,error}=await db.from("registrations").select("id,track_id,latest_status,companion_group_link_used_at,tracks(whatsapp_link)").eq("student_name_normalized",normalized).eq("track_id",trackId).order("updated_at",{ascending:false}).limit(1).maybeSingle();if(error)throw error;
   if(!row||row.latest_status!=="accepted")return json({error:"هذا الرابط متاح للطالبات المقبولات فقط."},403);const track:any=Array.isArray(row.tracks)?row.tracks[0]:row.tracks;const link=track?.whatsapp_link||"";if(!link)return json({error:"لم يتم إضافة رابط جروب الرفيقات لهذا المسار بعد."},404);if(row.companion_group_link_used_at)return json({error:"تم استخدام رابط جروب الرفيقات من قبل، ولا يمكن استخدامه مرة أخرى من الموقع."},409);
   const now=new Date().toISOString();const updated=await db.from("registrations").update({companion_group_link_used_at:now}).eq("id",row.id).is("companion_group_link_used_at",null).eq("latest_status","accepted").select("id").maybeSingle();if(updated.error)throw updated.error;if(!updated.data){const {data:check}=await db.from("registrations").select("companion_group_link_used_at,companion_group_link_use_count").eq("id",row.id).maybeSingle();const checkAt=check?.companion_group_link_used_at?new Date(check.companion_group_link_used_at).getTime():0;if((Number(check?.companion_group_link_use_count)||0)<1||(checkAt>0&&Date.now()-checkAt<15*60*1000))return Response.redirect(link,302);return json({error:"تم استخدام رابط جروب الرفيقات من قبل، ولا يمكن استخدامه مرة أخرى من الموقع."},409);}return Response.redirect(link,302);
  }
  if(action==="submit"){
   const form=await req.formData(),name=normalizeName(String(form.get("name")||"")),trackId=String(form.get("trackId")||""),audio=form.get("audio"),confirmedRetryId=String(form.get("confirmedRetryRegistrationId")||""),retryDecision=String(form.get("retryDecision")||"");
   if(!validName(name)||!trackId||!(audio instanceof File))return json({error:"بيانات التسجيل غير مكتملة."},400);
   if(audio.size<1000)return json({error:"التسجيل فارغ أو قصير جدًا."},400);
   if(audio.size>10*1024*1024)return json({error:"التسجيل أكبر من الحد المسموح (10 ميجابايت)."},400);
   const {data:track,error:trackError}=await db.from("tracks").select("id,name,is_open").eq("id",trackId).single();
   if(trackError||!track||!track.is_open)return json({error:"هذا المسار مغلق حاليًا."},400);
   const normalized=name.toLocaleLowerCase("ar-EG");
   const lookupKey=canonicalName(name);
   let {data:registration,error:regError}=await db.from("registrations").select("*").eq("track_id",trackId).order("updated_at",{ascending:false});
   if(regError)throw regError;
   const rows=registration||[];
   if(!confirmedRetryId&&retryDecision!=="no"){
     const retryCandidates=await findRetryNameCandidates(name,trackId);
     if(retryCandidates.length===1){
       return json({error:"وجدنا طالبة مسجلة باسم "+String(retryCandidates[0].student_name||"")+" وحالتها إعادة. هل أنتِ هذه الطالبة التي طلبت منها المعلمة إعادة التسجيل؟",code:"RETRY_NAME_CONFIRM",retryRegistrationId:String(retryCandidates[0].id),retryStudentName:String(retryCandidates[0].student_name||"")},409);
     }
     if(retryCandidates.length>1){
       return json({error:"يوجد أكثر من طالبة لها اسم قريب من الاسم المكتوب وحالتها إعادة. برجاء كتابة الاسم كما تم تسجيله كاملًا حتى نحدد الطالبة الصحيحة.",code:"RETRY_NAME_AMBIGUOUS"},409);
     }
   }else{
     const confirmed=rows.find((row:any)=>String(row.id)===confirmedRetryId&&row.latest_status==="retry");
     const enteredParts=canonicalParts(name),storedParts=canonicalParts(confirmed?.student_name||confirmed?.student_name_normalized||"");
     const prefixMatch=enteredParts.length>=2&&storedParts.length>enteredParts.length&&enteredParts.every((part:string,i:number)=>part===storedParts[i]);
     if(!confirmed||(!flexibleNamePartsMatch(name,String(confirmed.student_name||confirmed.student_name_normalized||""))&&!prefixMatch)){
       return json({error:"لا يمكن ربط التسجيل بطلب الإعادة بهذا الاسم. برجاء التأكد من الاسم.",code:"RETRY_NAME_CONFIRM_INVALID"},400);
     }
   }
   const literalRows=rows.filter((row:any)=>{
     const stored=row.student_name||row.student_name_normalized||"";
     return literalNamePartsMatch(name,stored);
   });
   const canonicalRows=rows.filter((row:any)=>{
     const stored=row.student_name||row.student_name_normalized||"";
     return canonicalName(stored)===lookupKey;
   });
   const flexibleRows=rows.filter((row:any)=>{
     const stored=row.student_name||row.student_name_normalized||"";
     return flexibleNamePartsMatch(name,stored);
   });
   const prioritizedRows=(rows:any[])=>rows.slice().sort((a:any,b:any)=>{
     const rank=(row:any)=>row?.latest_status==="retry"?0:row?.latest_status==="pending"?1:2;
     const rr=rank(a)-rank(b);
     if(rr!==0)return rr;
     return new Date(b?.updated_at||0).getTime()-new Date(a?.updated_at||0).getTime();
   });
   if(confirmedRetryId){
     registration=rows.find((row:any)=>String(row.id)===confirmedRetryId&&row.latest_status==="retry")||null;
   }else if(canonicalRows.length) registration=prioritizedRows(canonicalRows)[0];
   else if(literalRows.length) registration=prioritizedRows(literalRows)[0];
   else if(flexibleRows.length===1) registration=flexibleRows[0];
   else registration=null;
   if(registration?.latest_status==="pending")return json({error:"لديك تسجيل بالفعل قيد التقييم."},409);
   if(registration?.latest_status==="accepted"||registration?.latest_status==="rejected")return json({error:"تم تقييم آخر تسجيل لك بالفعل. يمكنك الرجوع لمعرفة النتيجة."},409);
   if(registration?.latest_status==="retry"){
     const aliases=Array.isArray(registration.result_aliases)?registration.result_aliases.slice():[];
     if(!aliases.some((alias:string)=>canonicalName(alias)===lookupKey))aliases.push(name);
     const linked=await db.from("registrations").update({result_aliases:aliases,latest_status:"pending",updated_at:new Date().toISOString()}).eq("id",registration.id).eq("latest_status","retry").select().single();
     if(linked.error)throw linked.error;
     registration=linked.data;
   }
   if(!registration){
     const {count:pendingCount,error:pendingError}=await db.from("registrations").select("id",{count:"exact",head:true}).eq("track_id",trackId).eq("latest_status","pending");
     if(pendingError)throw pendingError;
     if((pendingCount||0)>=50)return json({error:"يوجد عدد كبير من التسجيلات قيد التقييم حاليًا. برجاء المحاولة بعد قليل إن شاء الله."},429);
   }
   if(!registration||registration.latest_status==="retry"){
    const created=await db.from("registrations").insert({student_name:name,student_name_normalized:normalized,track_id:trackId,latest_status:"pending"}).select().single();if(created.error)throw created.error;registration=created.data;
   }
   const ext=audio.type.includes("ogg")?"ogg":audio.type.includes("mp4")?"mp4":"webm",path=`${registration.id}/${crypto.randomUUID()}.${ext}`;
   const upload=await db.storage.from(BUCKET).upload(path,new Uint8Array(await audio.arrayBuffer()),{contentType:audio.type||"audio/webm",upsert:false});
   if(upload.error){await db.from("registrations").update({latest_status:"retry",updated_at:new Date().toISOString()}).eq("id",registration.id);return json({error:"تعذر حفظ التسجيل حاليًا. مساحة التخزين أو الاتصال قد يكونان تحت ضغط، يرجى المحاولة لاحقًا."},503)}
   const inserted=await db.from("submissions").upsert({registration_id:registration.id,storage_path:path,mime_type:audio.type||"audio/webm"},{onConflict:"registration_id"});
   if(inserted.error){await db.storage.from(BUCKET).remove([path]);await db.from("registrations").update({latest_status:"retry",updated_at:new Date().toISOString()}).eq("id",registration.id);throw inserted.error}
   try{await checkPendingAlert(trackId)}catch(e){console.error("pending alert check failed",e)}
   return json({ok:true,message:"تم إرسال التسجيل للمعلمة بنجاح."});
  }
  if(action==="teacher-queue"){
   const body=await req.json();if(!(await requireRole(body,"teacher")))return json({error:"كلمة مرور المعلمة غير صحيحة."},401);
   const page=Math.max(1,Number(body.page)||1),pageSize=Math.min(50,Math.max(1,Number(body.pageSize)||20)),from=(page-1)*pageSize,to=from+pageSize-1;
   let q=db.from("submissions").select("id,storage_path,mime_type,created_at,registrations!inner(id,student_name,latest_status,track_id,tracks(id,name))",{count:"exact"}).eq("registrations.latest_status","pending").order("created_at",{ascending:true}).range(from,to);
   if(body.trackId)q=q.eq("registrations.track_id",String(body.trackId));
   const {data,error,count}=await q;if(error)throw error;
   const items=[];for(const row of data||[]){const reg:any=Array.isArray(row.registrations)?row.registrations[0]:row.registrations;const track:any=reg&&(Array.isArray(reg.tracks)?reg.tracks[0]:reg.tracks);const signed=await db.storage.from(BUCKET).createSignedUrl(row.storage_path,900);if(!signed.data?.signedUrl)continue;items.push({submissionId:row.id,studentName:reg?.student_name||"",trackName:track?.name||"",trackId:track?.id||"",createdAt:row.created_at,audioUrl:signed.data.signedUrl})}
   return json({items,total:count||0,page,pageSize,hasMore:(count||0)>to+1});
  }
  if(action==="evaluate"){
   const body=await req.json();if(!(await requireRole(body,"teacher")))return json({error:"كلمة مرور المعلمة غير صحيحة."},401);
   const status=String(body.status||"");const note=String(body.note||"").trim().slice(0,1000);if(!["accepted","rejected","retry"].includes(status))return json({error:"نتيجة غير صحيحة."},400);
   const {data:submission,error:se}=await db.from("submissions").select("id,registration_id,storage_path").eq("id",body.submissionId).single();if(se||!submission)return json({error:"التسجيل لم يعد موجودًا."},404);
   const {data:reg}=await db.from("registrations").select("id,latest_status").eq("id",submission.registration_id).single();if(!reg||reg.latest_status!=="pending")return json({error:"تم تقييم هذا التسجيل بالفعل."},409);
   const removed=await db.storage.from(BUCKET).remove([submission.storage_path]);
   if(removed.error)return json({error:"تعذر حذف ملف التسجيل من التخزين. لم يتم تثبيت نتيجة التقييم، يرجى المحاولة مرة أخرى."},503);
   const now=new Date().toISOString();
   const ev=await db.from("evaluations").insert({registration_id:submission.registration_id,status,note:status==="retry"?note:null,evaluated_at:now}).select("id").single();
   if(ev.error){await db.from("submissions").delete().eq("id",submission.id);await db.from("registrations").update({latest_status:"retry",updated_at:now}).eq("id",submission.registration_id);throw ev.error}
   const up=await db.from("registrations").update({latest_status:status,updated_at:now}).eq("id",submission.registration_id).eq("latest_status","pending");
   if(up.error){await db.from("evaluations").delete().eq("id",ev.data.id);await db.from("submissions").delete().eq("id",submission.id);await db.from("registrations").update({latest_status:"retry",updated_at:now}).eq("id",submission.registration_id);throw up.error}
   await db.from("submissions").delete().eq("id",submission.id);
   try{const {data:regAfter}=await db.from("registrations").select("track_id").eq("id",submission.registration_id).single();if(regAfter?.track_id)await checkPendingAlert(regAfter.track_id)}catch(e){console.error("pending alert reset check failed",e)}
   return json({ok:true,status});
  }
  if(action==="history"){const body=await req.json();if(!(await requireRole(body,"teacher")))return json({error:"كلمة مرور المعلمة غير صحيحة."},401);const {data,error}=await db.from("evaluations").select("id,status,evaluated_at,registrations(student_name,tracks(name))").order("evaluated_at",{ascending:false}).limit(200);if(error)throw error;return json({items:data||[]})}
  if(action==="admin-audit"){
   const body=await req.json();if(!(await requireRole(body,"admin")))return json({error:"كلمة مرور الإدارة غير صحيحة."},401);
   const {data,error}=await db.from("admin_audit_logs").select("id,action,track_id,details,created_at").order("created_at",{ascending:false}).limit(100);if(error)throw error;
   const trackIds=[...new Set((data||[]).map((x:any)=>x.track_id).filter(Boolean))];
   let tracksById:Record<string,string>={};
   if(trackIds.length){const {data:ts,error:te}=await db.from("tracks").select("id,name").in("id",trackIds);if(te)throw te;for(const t of ts||[])tracksById[t.id]=t.name;}
   return json({items:(data||[]).map((x:any)=>({...x,track_name:x.track_id?tracksById[x.track_id]||"":""}))});
  }
  if(action==="admin-student-evaluation"){const body=await req.json();if(!(await requireRole(body,"admin")))return json({error:"كلمة مرور الإدارة غير صحيحة."},401);const text=String(body.text||"").trim();const {error}=await db.from("app_settings").update({student_evaluation_text:text,updated_at:new Date().toISOString()}).eq("id",1);if(error)throw error;return json({ok:true,text});}
  if(action==="admin-change-status"){
   const body=await req.json();
   if(!(await requireRole(body,"admin")))return json({error:"كلمة مرور الإدارة غير صحيحة."},401);
   const registrationId=String(body.registrationId||""),newStatus=String(body.status||"");
   if(!registrationId||newStatus!=="rejected")return json({error:"بيانات تغيير الحالة غير صحيحة."},400);
   const {data:reg,error:re}=await db.from("registrations").select("id,student_name,track_id,latest_status").eq("id",registrationId).maybeSingle();
   if(re)throw re;
   if(!reg)return json({error:"الطالبة غير موجودة."},404);
   if(reg.latest_status!=="accepted")return json({error:"يمكن تغيير حالة الطالبة من مقبولة إلى مرفوضة فقط."},409);
   const now=new Date().toISOString();
   const up=await db.from("registrations").update({latest_status:"rejected",updated_at:now}).eq("id",registrationId).eq("latest_status","accepted");
   if(up.error)throw up.error;
   await audit("admin-correct-status",reg.track_id,{registrationId,studentName:reg.student_name,from:"accepted",to:"rejected"});
   return json({ok:true,status:"rejected"});
  }
  if(action==="admin-search-student"){
   const body=await req.json();
   if(!(await requireRole(body,"admin")))return json({error:"كلمة مرور الإدارة غير صحيحة."},401);
   const q=String(body.query||"").trim().replace(/\s+/g," ");
   if(!q)return json({students:[],tracks:[],companionPairs:[]});
   const {data:tracks,error:te}=await db.from("tracks").select("id,name").order("sort_order");
   if(te)throw te;
   const pattern="%"+q+"%";
   const {data:regs,error:re}=await db.from("registrations").select("id,student_name,student_name_normalized,track_id,latest_status,companion_group_link_use_count").or("student_name.ilike."+pattern+",student_name_normalized.ilike."+pattern).order("updated_at",{ascending:false}).limit(50);
   if(re)throw re;
   const ids=(regs||[]).map((r:any)=>r.id);
   let pairs:any[]=[];
   if(ids.length){
     const {data:p,error:pe}=await db.from("companion_pairs").select("id,riwaya,pair_number,student1_registration_id,student2_registration_id").or("student1_registration_id.in.("+ids.join(",")+"),student2_registration_id.in.("+ids.join(",")+")");
     if(pe)throw pe;
     pairs=p||[];
   }
   const otherIds=[...new Set(pairs.flatMap((p:any)=>[p.student1_registration_id,p.student2_registration_id]))].filter((id:string)=>!ids.includes(id));
   if(otherIds.length){
     const {data:other,error:oe}=await db.from("registrations").select("id,student_name,track_id").in("id",otherIds);
     if(oe)throw oe;
     for(const r of other||[]) (regs as any[]).push({...r,latest_status:""});
   }
   const byId:Record<string,any>={};
   for(const r of regs||[])byId[r.id]=r;
   return json({
     students:(regs||[]).slice(0,50).map((r:any)=>({id:r.id,studentName:r.student_name,trackId:r.track_id,status:r.latest_status,companionGroupLinkUseCount:Number(r.companion_group_link_use_count)||0})),
     tracks:tracks||[],
     companionPairs:pairs.map((p:any)=>({id:p.id,riwaya:p.riwaya,pairNumber:p.pair_number,student1RegistrationId:p.student1_registration_id,student2RegistrationId:p.student2_registration_id,student1Name:byId[p.student1_registration_id]?.student_name||"",student2Name:byId[p.student2_registration_id]?.student_name||""}))
   });
  }
  if(action==="admin-data"){
   const body=await req.json();if(!(await requireRole(body,"admin")))return json({error:"كلمة مرور الإدارة غير صحيحة."},401);
   const {data:tracks,error}=await db.from("tracks").select("*").order("sort_order");if(error)throw error;
   const {data:regs,error:re}=await db.from("registrations").select("id,student_name,track_id,latest_status");if(re)throw re;
   const {data:pairs,error:pe}=await db.from("companion_pairs").select("id,riwaya,pair_number,student1_registration_id,student2_registration_id");if(pe)throw pe;
   const stats:Record<string,any>={};for(const t of tracks||[])stats[t.id]={accepted:0,rejected:0,pending:0,retry:0};
   for(const r of regs||[])if(stats[r.track_id])stats[r.track_id][r.latest_status]=(stats[r.track_id][r.latest_status]||0)+1;
   const students=(regs||[]).map((r:any)=>({id:r.id,studentName:r.student_name,trackId:r.track_id,status:r.latest_status}));
   const acceptedStudents=students.filter((r:any)=>r.status==="accepted");
   const byId:Record<string,any>={};for(const r of regs||[])byId[r.id]=r;
   const companionPairs=(pairs||[]).map((p:any)=>({id:p.id,riwaya:p.riwaya,pairNumber:p.pair_number,student1RegistrationId:p.student1_registration_id,student2RegistrationId:p.student2_registration_id,student1Name:byId[p.student1_registration_id]?.student_name||"",student2Name:byId[p.student2_registration_id]?.student_name||"",trackId:byId[p.student1_registration_id]?.track_id||""})).filter((p:any)=>p.trackId);
   return json({tracks:(tracks||[]).map(t=>({...t,stats:stats[t.id]})),rejectionMessage:REJECTION_MESSAGE,students,acceptedStudents,companionPairs});
  }
  if(action==="edit-companion-list"){
   const body=await req.json();if(!(await requireRole(body,"admin")))return json({error:"كلمة مرور الإدارة غير صحيحة."},401);
   const trackId=String(body.trackId||""),pairs=Array.isArray(body.pairs)?body.pairs:[];
   if(!trackId)return json({error:"المسار غير محدد."},400);
   const {data:accepted,error:ae}=await db.from("registrations").select("id,student_name,track_id,latest_status").eq("track_id",trackId).eq("latest_status","accepted");if(ae)throw ae;
   const allowed=new Set((accepted||[]).map((x:any)=>x.id)),used=new Set<string>(),usedNumbers=new Set<number>();
   for(const p of pairs){
     const pairNumber=Number(String(p.pairNumber||""));
     if(!p||!allowed.has(String(p.student1Id))||!allowed.has(String(p.student2Id)))return json({error:"كل الطالبات في القائمة يجب أن يكن مقبولات وفي نفس المسار."},400);
     if(String(p.student1Id)===String(p.student2Id))return json({error:"لا يمكن أن تكون الطالبة رفيقة لنفسها."},400);
     if(!Number.isInteger(pairNumber)||pairNumber<1)return json({error:"رقم الرفيقة يجب أن يكون رقمًا صحيحًا أكبر من صفر."},400);
     if(!["حفص","قالون"].includes(String(p.riwaya)))return json({error:"الرواية غير صحيحة."},400);
     if(used.has(String(p.student1Id))||used.has(String(p.student2Id)))return json({error:"لا يمكن تكرار نفس الطالبة في أكثر من رفيقة."},400);
     if(usedNumbers.has(pairNumber))return json({error:"لا يمكن تكرار نفس رقم الرفيقة في القائمة."},400);
     used.add(String(p.student1Id));used.add(String(p.student2Id));usedNumbers.add(pairNumber);
   }
   const {data:allPairs,error:pe}=await db.from("companion_pairs").select("id,student1_registration_id,student2_registration_id");if(pe)throw pe;
   const oldIds=(allPairs||[]).filter((p:any)=>allowed.has(p.student1_registration_id)||allowed.has(p.student2_registration_id)).map((p:any)=>p.id);
   if(oldIds.length){const del=await db.from("companion_pairs").delete().in("id",oldIds);if(del.error)throw del.error;}
   if(pairs.length){const ins=await db.from("companion_pairs").insert(pairs.map((p:any)=>({student1_registration_id:String(p.student1Id),student2_registration_id:String(p.student2Id),riwaya:String(p.riwaya),pair_number:Number(String(p.pairNumber||""))})));if(ins.error)throw ins.error;}
   await audit("edit-companion-list",trackId,{pairCount:pairs.length});
   return json({ok:true,count:pairs.length});
  }
  if(action==="admin-reset-companion-link"){
   const body=await req.json();if(!(await requireRole(body,"admin")))return json({error:"كلمة مرور الإدارة غير صحيحة."},401);
   const registrationId=String(body.registrationId||"");
   if(!registrationId)return json({error:"الطالبة غير محددة."},400);
   const {data:r,error}=await db.from("registrations").update({companion_group_link_use_count:0,companion_group_link_used_at:null}).eq("id",registrationId).eq("latest_status","accepted").select("id,student_name,companion_group_link_use_count").maybeSingle();
   if(error)throw error;
   if(!r)return json({error:"لا يمكن إعادة فتح الرابط إلا للطالبة المقبولة."},400);
   await audit("admin-reset-companion-link",registrationId,{});
   return json({ok:true,studentName:r.student_name,useCount:0});
  }
  if(action==="admin-track"){
   const body=await req.json();if(!(await requireRole(body,"admin")))return json({error:"كلمة مرور الإدارة غير صحيحة."},401);
   const op=String(body.op||"");
   if(op==="create"){const name=String(body.name||"").trim();if(!name)return json({error:"اسم المسار مطلوب."},400);const {data:maxRow}=await db.from("tracks").select("sort_order").order("sort_order",{ascending:false}).limit(1).maybeSingle();const r=await db.from("tracks").insert({name,whatsapp_link:String(body.whatsappLink||"").trim(),primary_group_link:String(body.primaryGroupLink||"").trim(),is_open:true,sort_order:(maxRow?.sort_order||0)+1}).select().single();if(r.error)throw r.error;await audit("create-track",r.data.id,{name:r.data.name});return json({track:r.data})}
   if(op==="update"){const r=await db.from("tracks").update({name:String(body.name||"").trim(),whatsapp_link:String(body.whatsappLink||"").trim(),primary_group_link:String(body.primaryGroupLink||"").trim(),is_open:!!body.isOpen,teacher1_name:String(body.teacher1Name||"").trim(),teacher2_name:String(body.teacher2Name||"").trim(),teacher3_name:String(body.teacher3Name||"").trim(),teacher4_name:String(body.teacher4Name||"").trim(),updated_at:new Date().toISOString()}).eq("id",body.id).select().single();if(r.error)throw r.error;await audit("update-track",String(body.id),{name:r.data.name,isOpen:r.data.is_open,teachers:[r.data.teacher1_name,r.data.teacher2_name,r.data.teacher3_name,r.data.teacher4_name].filter(Boolean)});return json({track:r.data})}
   return json({error:"عملية غير معروفة."},400)
  }
  if(action==="reset-results"){
   const body=await req.json();if(!(await requireRole(body,"admin")))return json({error:"كلمة مرور الإدارة غير صحيحة."},401);
   const {data:subs,error:se}=await db.from("submissions").select("storage_path");
   if(se)throw se;
   const paths=(subs||[]).map((x:any)=>x.storage_path).filter(Boolean);
   if(paths.length){const removed=await db.storage.from(BUCKET).remove(paths);if(removed.error)return json({error:"تعذر حذف بعض ملفات التسجيلات، لذلك لم يتم حذف النتائج."},503);}
   const ev=await db.from("evaluations").delete().not("id","is",null);if(ev.error)throw ev.error;
   const subDel=await db.from("submissions").delete().not("id","is",null);if(subDel.error)throw subDel.error;
   const regDel=await db.from("registrations").delete().not("id","is",null);if(regDel.error)throw regDel.error;
   await audit("reset-results",null,{});
   return json({ok:true,message:"تم مسح جميع النتائج والتسجيلات السابقة."});
  }
  if(action==="change-passwords"){const body=await req.json();if(!(await requireRole(body,"admin")))return json({error:"كلمة مرور الإدارة غير صحيحة."},401);const update:any={updated_at:new Date().toISOString()};if(body.teacherPassword)update.teacher_password_hash=await sha256(String(body.teacherPassword));if(body.adminPassword)update.admin_password_hash=await sha256(String(body.adminPassword));const r=await db.from("app_settings").update(update).eq("id",1);if(r.error)throw r.error;await audit("change-passwords",null,{teacherPasswordChanged:!!body.teacherPassword,adminPasswordChanged:!!body.adminPassword});return json({ok:true})}
  return json({error:"طلب غير معروف."},404);
 }catch(e){console.error(e);return json({error:e?.message||"حدث خطأ غير متوقع."},500)}
});
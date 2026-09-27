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
function normalizeName(name:string){return name.trim().replace(/\s+/g," ").replace(/ة$/u,"ه")}
function validName(name:string){return normalizeName(name).length>0}
async function getOpenTracks(){const {data,error}=await db.from("tracks").select("id,name,whatsapp_link,is_open,sort_order").eq("is_open",true).order("sort_order");if(error)throw error;return data||[]}
async function getResult(name:string){
 const normalized=normalizeName(name).toLocaleLowerCase("ar-EG");
 const {data,error}=await db.from("registrations").select("id,student_name,latest_status,updated_at,companion_group_link_used_at,tracks(name,whatsapp_link)").eq("student_name_normalized",normalized).order("updated_at",{ascending:false}).limit(1);
 if(error)throw error; const row=data?.[0]; if(!row)return {found:false};
 const track:any=Array.isArray(row.tracks)?row.tracks[0]:row.tracks;
 return {found:true,studentName:row.student_name,trackName:track?.name||"",status:row.latest_status,whatsappLink:row.latest_status==="accepted"?(track?.whatsapp_link||""):"",companionGroupLinkUsed:!!row.companion_group_link_used_at,rejectionMessage:row.latest_status==="rejected"?REJECTION_MESSAGE:""};
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
  if(action==="result"){const body=await req.json();const name=normalizeName(String(body.name||""));if(!validName(name))return json({error:"برجاء إدخال الاسم."},400);return json(await getResult(name))}
  if(action==="register-companion"){
   const body=await req.json(),name=normalizeName(String(body.name||"")),name2=normalizeName(String(body.name2||"")),riwaya=String(body.riwaya||"");
   if(!validName(name)||!validName(name2)||!["حفص","قالون"].includes(riwaya))return json({error:"بيانات الرفقة غير مكتملة."},400);
   const n1=name.toLocaleLowerCase("ar-EG"),n2=name2.toLocaleLowerCase("ar-EG");
   if(n1===n2)return json({error:"لا يمكن تسجيل الطالبة مع نفسها."},400);
   const getAccepted=async(n:string)=>{const {data,error}=await db.from("registrations").select("id,student_name,student_name_normalized,track_id,latest_status,tracks(name,primary_group_link)").eq("student_name_normalized",n).order("updated_at",{ascending:false}).limit(1).maybeSingle();if(error)throw error;return data};
   const a:any=await getAccepted(n1),b:any=await getAccepted(n2);
   if(!a||a.latest_status!=="accepted")return json({error:"الطالبة الأولى غير موجودة ضمن الطالبات المقبولات."},403);
   if(!b||b.latest_status!=="accepted")return json({error:"الطالبة الثانية غير موجودة ضمن الطالبات المقبولات."},403);
   if(a.track_id!==b.track_id)return json({error:"يجب أن تكون الطالبتان من نفس المسار."},400);
   const {data:existing,error:pe}=await db.from("companion_pairs").select("id,student1_registration_id,student2_registration_id");if(pe)throw pe;
   if((existing||[]).some((p:any)=>p.student1_registration_id===a.id||p.student2_registration_id===a.id||p.student1_registration_id===b.id||p.student2_registration_id===b.id))return json({error:"إحدى الطالبتين مسجلة بالفعل مع رفيقة أخرى."},409);
   const inserted=await db.from("companion_pairs").insert({student1_registration_id:a.id,student2_registration_id:b.id,riwaya}).select("id").single();if(inserted.error)throw inserted.error;
   const sameTrack=(existing||[]).filter((p:any)=>[a.id,b.id].includes(p.student1_registration_id)||[a.id,b.id].includes(p.student2_registration_id));
   const pairNumber=(existing||[]).filter((p:any)=>p.student1_registration_id===a.id||p.student2_registration_id===a.id||p.student1_registration_id===b.id||p.student2_registration_id===b.id).length+1;
   return json({ok:true,pairNumber:pairNumber,student1Name:a.student_name,student2Name:b.student_name,riwaya,primaryGroupLink:(Array.isArray(a.tracks)?a.tracks[0]:a.tracks)?.primary_group_link||""});
  }
  if(action==="use-companion-group-link"){
   const body=await req.json(),name=normalizeName(String(body.name||""));if(!validName(name))return json({error:"برجاء إدخال الاسم."},400);
   const normalized=name.toLocaleLowerCase("ar-EG");
   const {data:row,error}=await db.from("registrations").select("id,latest_status,companion_group_link_used_at,tracks(whatsapp_link)").eq("student_name_normalized",normalized).order("updated_at",{ascending:false}).limit(1).maybeSingle();if(error)throw error;
   if(!row||row.latest_status!=="accepted")return json({error:"هذا الرابط متاح للطالبات المقبولات فقط."},403);const track:any=Array.isArray(row.tracks)?row.tracks[0]:row.tracks;const link=track?.whatsapp_link||"";if(!link)return json({error:"لم يتم إضافة رابط جروب الرفيقات لهذا المسار بعد."},404);if(row.companion_group_link_used_at)return json({error:"تم استخدام رابط جروب الرفيقات من قبل، ولا يمكن استخدامه مرة أخرى من الموقع."},409);
   const now=new Date().toISOString();const updated=await db.from("registrations").update({companion_group_link_used_at:now}).eq("id",row.id).is("companion_group_link_used_at",null).eq("latest_status","accepted").select("id").maybeSingle();if(updated.error)throw updated.error;if(!updated.data)return json({error:"تم استخدام رابط جروب الرفيقات من قبل، ولا يمكن استخدامه مرة أخرى من الموقع."},409);return json({ok:true,whatsappLink:link});
  }
  if(action==="submit"){
   const form=await req.formData(),name=normalizeName(String(form.get("name")||"")),trackId=String(form.get("trackId")||""),audio=form.get("audio");
   if(!validName(name)||!trackId||!(audio instanceof File))return json({error:"بيانات التسجيل غير مكتملة."},400);
   if(audio.size<1000)return json({error:"التسجيل فارغ أو قصير جدًا."},400);
   if(audio.size>10*1024*1024)return json({error:"التسجيل أكبر من الحد المسموح (10 ميجابايت)."},400);
   const {data:track,error:trackError}=await db.from("tracks").select("id,name,is_open").eq("id",trackId).single();
   if(trackError||!track||!track.is_open)return json({error:"هذا المسار مغلق حاليًا."},400);
   const normalized=name.toLocaleLowerCase("ar-EG");
   let {data:registration,error:regError}=await db.from("registrations").select("*").eq("track_id",trackId).eq("student_name_normalized",normalized).maybeSingle();
   if(regError)throw regError;
   if(registration?.latest_status==="pending")return json({error:"لديك تسجيل بالفعل قيد التقييم."},409);
   if(registration?.latest_status==="accepted"||registration?.latest_status==="rejected")return json({error:"تم تقييم آخر تسجيل لك بالفعل. يمكنك الرجوع لمعرفة النتيجة."},409);
   if(!registration){
    const created=await db.from("registrations").insert({student_name:name,student_name_normalized:normalized,track_id:trackId,latest_status:"pending"}).select().single();if(created.error)throw created.error;registration=created.data;
   }else{
    const updated=await db.from("registrations").update({latest_status:"pending",updated_at:new Date().toISOString()}).eq("id",registration.id).select().single();if(updated.error)throw updated.error;registration=updated.data;
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
   const status=String(body.status||"");if(!["accepted","rejected","retry"].includes(status))return json({error:"نتيجة غير صحيحة."},400);
   const {data:submission,error:se}=await db.from("submissions").select("id,registration_id,storage_path").eq("id",body.submissionId).single();if(se||!submission)return json({error:"التسجيل لم يعد موجودًا."},404);
   const {data:reg}=await db.from("registrations").select("id,latest_status").eq("id",submission.registration_id).single();if(!reg||reg.latest_status!=="pending")return json({error:"تم تقييم هذا التسجيل بالفعل."},409);
   const removed=await db.storage.from(BUCKET).remove([submission.storage_path]);
   if(removed.error)return json({error:"تعذر حذف ملف التسجيل من التخزين. لم يتم تثبيت نتيجة التقييم، يرجى المحاولة مرة أخرى."},503);
   const now=new Date().toISOString();
   const ev=await db.from("evaluations").insert({registration_id:submission.registration_id,status,evaluated_at:now}).select("id").single();
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
  if(action==="admin-data"){
   const body=await req.json();if(!(await requireRole(body,"admin")))return json({error:"كلمة مرور الإدارة غير صحيحة."},401);
   const {data:tracks,error}=await db.from("tracks").select("*").order("sort_order");if(error)throw error;
   const {data:regs,error:re}=await db.from("registrations").select("id,student_name,track_id,latest_status");if(re)throw re;
   const {data:pairs,error:pe}=await db.from("companion_pairs").select("id,riwaya,student1_registration_id,student2_registration_id");if(pe)throw pe;
   const stats:Record<string,any>={};for(const t of tracks||[])stats[t.id]={accepted:0,rejected:0,pending:0,retry:0};
   for(const r of regs||[])if(stats[r.track_id])stats[r.track_id][r.latest_status]=(stats[r.track_id][r.latest_status]||0)+1;
   const students=(regs||[]).map((r:any)=>({id:r.id,studentName:r.student_name,trackId:r.track_id,status:r.latest_status}));
   const acceptedStudents=students.filter((r:any)=>r.status==="accepted");
   const byId:Record<string,any>={};for(const r of regs||[])byId[r.id]=r;
   const companionPairs=(pairs||[]).map((p:any)=>({id:p.id,riwaya:p.riwaya,student1RegistrationId:p.student1_registration_id,student2RegistrationId:p.student2_registration_id,student1Name:byId[p.student1_registration_id]?.student_name||"",student2Name:byId[p.student2_registration_id]?.student_name||"",trackId:byId[p.student1_registration_id]?.track_id||""})).filter((p:any)=>p.trackId);
   return json({tracks:(tracks||[]).map(t=>({...t,stats:stats[t.id]})),rejectionMessage:REJECTION_MESSAGE,students,acceptedStudents,companionPairs});
  }
  if(action==="edit-companion-list"){
   const body=await req.json();if(!(await requireRole(body,"admin")))return json({error:"كلمة مرور الإدارة غير صحيحة."},401);
   const trackId=String(body.trackId||""),pairs=Array.isArray(body.pairs)?body.pairs:[];
   if(!trackId)return json({error:"المسار غير محدد."},400);
   const {data:accepted,error:ae}=await db.from("registrations").select("id,student_name,track_id,latest_status").eq("track_id",trackId).eq("latest_status","accepted");if(ae)throw ae;
   const allowed=new Set((accepted||[]).map((x:any)=>x.id)),used=new Set<string>();
   for(const p of pairs){
     if(!p||!allowed.has(String(p.student1Id))||!allowed.has(String(p.student2Id)))return json({error:"كل الطالبات في القائمة يجب أن يكن مقبولات وفي نفس المسار."},400);
     if(String(p.student1Id)===String(p.student2Id))return json({error:"لا يمكن أن تكون الطالبة رفيقة لنفسها."},400);
     if(!["حفص","قالون"].includes(String(p.riwaya)))return json({error:"الرواية غير صحيحة."},400);
     if(used.has(String(p.student1Id))||used.has(String(p.student2Id)))return json({error:"لا يمكن تكرار نفس الطالبة في أكثر من رفيقة."},400);
     used.add(String(p.student1Id));used.add(String(p.student2Id));
   }
   const {data:allPairs,error:pe}=await db.from("companion_pairs").select("id,student1_registration_id,student2_registration_id");if(pe)throw pe;
   const oldIds=(allPairs||[]).filter((p:any)=>allowed.has(p.student1_registration_id)||allowed.has(p.student2_registration_id)).map((p:any)=>p.id);
   if(oldIds.length){const del=await db.from("companion_pairs").delete().in("id",oldIds);if(del.error)throw del.error;}
   if(pairs.length){const ins=await db.from("companion_pairs").insert(pairs.map((p:any)=>({student1_registration_id:String(p.student1Id),student2_registration_id:String(p.student2Id),riwaya:String(p.riwaya)})));if(ins.error)throw ins.error;}
   await audit("edit-companion-list",trackId,{pairCount:pairs.length});
   return json({ok:true,count:pairs.length});
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
import { createClient } from "npm:@supabase/supabase-js@2";

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
  if(action==="tracks")return json({tracks:await getOpenTracks()});
  if(action==="all-tracks"){const body=await req.json();if(!(await requireRole(body,"teacher")))return json({error:"كلمة مرور المعلمة غير صحيحة."},401);const {data,error}=await db.from("tracks").select("id,name").order("sort_order");if(error)throw error;return json({tracks:data||[]})}
  if(action==="result"){const body=await req.json();const name=normalizeName(String(body.name||""));if(!validName(name))return json({error:"برجاء إدخال الاسم."},400);return json(await getResult(name))}
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
   return json({ok:true,status});
  }
  if(action==="history"){const body=await req.json();if(!(await requireRole(body,"teacher")))return json({error:"كلمة مرور المعلمة غير صحيحة."},401);const {data,error}=await db.from("evaluations").select("id,status,evaluated_at,registrations(student_name,tracks(name))").order("evaluated_at",{ascending:false}).limit(200);if(error)throw error;return json({items:data||[]})}
  if(action==="admin-data"){
   const body=await req.json();if(!(await requireRole(body,"admin")))return json({error:"كلمة مرور الإدارة غير صحيحة."},401);
   const {data:tracks,error}=await db.from("tracks").select("*").order("sort_order");if(error)throw error;
   const {data:regs,error:re}=await db.from("registrations").select("track_id,latest_status");if(re)throw re;
   const stats:Record<string,any>={};for(const t of tracks||[])stats[t.id]={accepted:0,rejected:0,pending:0,retry:0};
   for(const r of regs||[])if(stats[r.track_id])stats[r.track_id][r.latest_status]=(stats[r.track_id][r.latest_status]||0)+1;
   return json({tracks:(tracks||[]).map(t=>({...t,stats:stats[t.id]})),rejectionMessage:REJECTION_MESSAGE});
  }
  if(action==="admin-track"){
   const body=await req.json();if(!(await requireRole(body,"admin")))return json({error:"كلمة مرور الإدارة غير صحيحة."},401);
   const op=String(body.op||"");
   if(op==="create"){const name=String(body.name||"").trim();if(!name)return json({error:"اسم المسار مطلوب."},400);const {data:maxRow}=await db.from("tracks").select("sort_order").order("sort_order",{ascending:false}).limit(1).maybeSingle();const r=await db.from("tracks").insert({name,whatsapp_link:String(body.whatsappLink||"").trim(),is_open:true,sort_order:(maxRow?.sort_order||0)+1}).select().single();if(r.error)throw r.error;return json({track:r.data})}
   if(op==="update"){const r=await db.from("tracks").update({name:String(body.name||"").trim(),whatsapp_link:String(body.whatsappLink||"").trim(),is_open:!!body.isOpen,updated_at:new Date().toISOString()}).eq("id",body.id).select().single();if(r.error)throw r.error;return json({track:r.data})}
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
   return json({ok:true,message:"تم مسح جميع النتائج والتسجيلات السابقة."});
  }
  if(action==="change-passwords"){const body=await req.json();if(!(await requireRole(body,"admin")))return json({error:"كلمة مرور الإدارة غير صحيحة."},401);const update:any={updated_at:new Date().toISOString()};if(body.teacherPassword)update.teacher_password_hash=await sha256(String(body.teacherPassword));if(body.adminPassword)update.admin_password_hash=await sha256(String(body.adminPassword));const r=await db.from("app_settings").update(update).eq("id",1);if(r.error)throw r.error;return json({ok:true})}
  return json({error:"طلب غير معروف."},404);
 }catch(e){console.error(e);return json({error:e?.message||"حدث خطأ غير متوقع."},500)}
});
  /* ===== i18n ===== */
  const translations = {
    pageTitle:{fa:'NEXA Panel · مستندات', en:'NEXA Panel · Docs'},
    pageDesc:{fa:'مستندات رسمی NEXA Panel — پنل مدیریتی سبک روی Cloudflare Workers', en:'Official NEXA Panel documentation — a light admin panel on Cloudflare Workers'},
    langToggleTitle:{fa:'Switch to English', en:'تغییر به فارسی'},
    themeToLight:{fa:'حالت روشن', en:'Light mode'},
    themeToDark:{fa:'حالت تاریک', en:'Dark mode'},
    menuOpenTitle:{fa:'باز کردن منو', en:'Open menu'},
    menuCloseTitle:{fa:'بستن منو', en:'Close menu'},
    searchPlaceholder:{fa:'جستوجو ...', en:'Search …'},
    searchNoMatch:{fa:'چیزی پیدا نشد', en:'No results found'},
    ovImgCaption:{fa:'نمایی از داشبورد پنل', en:'A view of the panel dashboard'},
    navStart:{fa:'خانه', en:'Home'},
    depimg:{fa:'نمایی از داشبورد پنل', en:'A view of the Panel Dashboard'},
    navOverview:{fa:'معرفی', en:'Overview'},
    navFeatures:{fa:'ویژگی‌ها', en:'Features'},
    navSetup:{fa:'نصب و راه‌اندازی', en:'Setup'},
    navQuickDeploy:{fa:'نصب سریع', en:'Quick Deploy'},
    navManualInstall:{fa:'نصب دستی', en:'Manual Install'},
    navGuide:{fa:'راهنمای پنل', en:'Panel Guide'},
    navGuideDashboard:{fa:'داشبورد', en:'Dashboard'},
    navGuideUsers:{fa:'مدیریت کاربران', en:'User Management'},
    navGuideConnect:{fa:'آموزش اتصال', en:'Connection Guide'},
    navGuideNode:{fa:'سرور نود', en:'Node Server'},
    navGuideIpscan:{fa:'اسکنر IP تمیز', en:'Clean IP Scanner'},
    navGuideCdn:{fa:'پروکسی CDN', en:'CDN Proxy'},
    navGuideLogs:{fa:'لاگ فعالیت', en:'Activity Log'},
    navGuideSettings:{fa:'تنظیمات پنل', en:'Panel Settings'},
    navCommunity:{fa:'جامعه و منابع', en:'Community & Resources'},
    navLinks:{fa:'لینک های کاربردی', en:'Useful Links'},
    navSupport:{fa:'حمایت مالی', en:'Support Us'},
    navLicense:{fa:'لایسنس', en:'License'},
    gDashPart1T:{fa:'لینک اشتراک اصلی', en:'Main subscription link'},
    gDashPart1D:{fa:'در این قسمت شما میتوانید به اشتراک اصلی پنل خود دسترسی داشته باشید', en:"In this section you can access your main panel share."},
    gDashPart2T:{fa:'نمایش مصرف ریکوئست', en:'Show request usage'},
    gDashPart2D:{fa:'در این قسمت میتوانید مصرف ریکوئست کل و کاربران خود را ببینید', en:"In this section you can see the total request consumption and your users."},
    gDashPart3T:{fa:'نمایش ایپی شما', en:'Show your IP'},
    gDashPart3D:{fa:'نمایش ایپی شما و نمایش موقعیت تقریبی شما روی نقشه', en:"Show your IP and show your approximate location on the map"},
    gUsersPart1T:{fa:'نمایش وضعیت سرویس‌ها و کاربران', en:'Show status of services and users'},
gUsersPart1D:{fa:'نمایش وضعیت سرویس‌ها و کاربران و مدیریت و ویرایش آن‌ها', en:'Shows the status of services and users, and lets you manage and edit them.'},
gSetPart1T:{fa:'به‌روزرسانی پنل', en:'Panel update'},
gSetPart1D:{fa:'در این بخش نسخه‌ی فعلی پنل شما و آخرین نسخه‌ی موجود روی سرور نمایش داده می‌شود. با زدن دکمه‌ی «به‌روزرسانی پنل»، آخرین تغییرات و ویژگی‌های جدید روی پنل شما نصب می‌شود.', en:'This section shows your current panel version and the latest version available on the server. Clicking "Update Panel" installs the latest changes and new features.'},

gSetPart2T:{fa:'قطع اضطراری تمامی سرویس‌ها', en:'Emergency stop all services'},
gSetPart2D:{fa:'با فعال کردن این گزینه، دسترسی تمام کاربران به‌صورت لحظه‌ای قطع می‌شود؛ مناسب مواقعی که نیاز به توقف سریع کل سرویس‌ها دارید. برای بازگرداندن دسترسی، کافیست همین گزینه را دوباره غیرفعال کنید.', en:'Enabling this instantly cuts off access for all users — useful when you need to stop everything quickly. Disable it again to restore access.'},

gSetPart3T:{fa:'تنظیمات آدرس صفحات', en:'Page path settings'},
gSetPart3D:{fa:'از این قسمت می‌توانید مسیر ورود به پنل مدیریت و همچنین آدرس صفحات وضعیت سرویس، لینک اشتراک (ساب) و لاگ اتصال کاربران را به دلخواه خودتان تغییر دهید تا شناسایی و حدس زدن آن‌ها برای دیگران سخت‌تر شود.', en:'Here you can customize the admin panel login path, plus the status page, subscription (sub), and connection log paths — making them harder for others to guess.'},

gSetPart4T:{fa:'نام‌گذاری کانفیگ‌ها', en:'Config naming'},
gSetPart4D:{fa:'در این بخش می‌توانید قالب نام کانفیگ‌ها و مشخصات نمایشی سرویس (مثل حجم مصرفی، حجم کل، روزهای باقی‌مانده و پورت) را با استفاده از متغیرهایی مانند {used}، {total} و {dayremind} شخصی‌سازی کنید.', en:'Customize the config name template and displayed service details (used volume, total volume, remaining days, port) using variables like {used}, {total}, and {dayremind}.'},

gSetPart5T:{fa:'بکاپ‌گیری از پنل', en:'Panel backup'},
gSetPart5D_1:{fa:'می‌توانید یک نسخه‌ی پشتیبان کامل از کاربران، تنظیمات و لاگ‌های پنل دریافت یا یک بکاپ قبلی را بارگذاری کنید.', en:'Download a full backup of users, settings, and logs, or upload a previous backup.'},
gSetPart5D_2:{fa:'با فعال کردن «بکاپ خودکار روزانه» و وارد کردن توکن ربات تلگرام و شناسه چت، پنل هر روز رأس ساعت مشخص‌شده یک بکاپ کامل برای شما به تلگرام ارسال می‌کند.', en:'Enable "Daily Auto Backup" and enter your Telegram bot token and chat ID to receive a full backup on Telegram every day at the set time.'},
gSetPart5D_3:{fa:'گزینه‌ی «بازنشانی تمام تنظیمات» تمام کاربران، پروکسی‌ها، تنظیمات تلگرام و لاگ‌ها را پاک کرده و پنل را به حالت اولیه بازمی‌گرداند؛ این عملیات غیرقابل بازگشت است.', en:'"Reset All Settings" deletes all users, proxies, Telegram settings, and logs, returning the panel to its initial state — this action is irreversible.'},

gSetPart6T:{fa:'مسدودسازی دامنه و فیلتر محتوای بزرگسال', en:'Domain blocking & adult content filter'},
gSetPart6D_1:{fa:'در این قسمت می‌توانید فهرستی از دامنه‌ها را وارد کنید تا کاربران پنل نتوانند از طریق پروکسی به آن‌ها متصل شوند؛ با مسدود کردن هر دامنه، تمام زیردامنه‌های آن نیز مسدود خواهند شد.', en:'Enter a list of domains to block for all users; blocking a domain also blocks all its subdomains.'},
gSetPart6D_2:{fa:'با فعال کردن «مسدودسازی محتوای بزرگسال»، دسترسی به سایت‌های دارای محتوای نامناسب (۱۸+) برای تمام کاربران پنل به‌صورت خودکار مسدود می‌شود.', en:'Enabling "Adult Content Filter" automatically blocks access to (18+) sites for all panel users.'},

gSetPart7T:{fa:'تنظیمات Cloudflare API', en:'Cloudflare API settings'},
gSetPart7D:{fa:'با وارد کردن CF_TOKEN، پنل به‌صورت خودکار به حساب Cloudflare شما متصل شده و Account ID را دریافت می‌کند؛ این توکن برای ساخت و مدیریت خودکار سرورهای نود و سایر عملیات ورکر لازم است و نیازی به وارد کردن دستی Account ID نیست.', en:'Entering CF_TOKEN automatically connects the panel to your Cloudflare account and fetches the Account ID. This token is required for automatic node server management and other Worker operations — no need to enter the Account ID manually.'},

gSetPart8T:{fa:'تغییر رمز عبور مدیریت', en:'Change admin password'},
gSetPart8D:{fa:'برای افزایش امنیت پنل، می‌توانید رمز عبور ورود به بخش مدیریت را از همین قسمت تغییر دهید. رمز عبور جدید در متغیر محیطی ADMIN در Cloudflare Workers ذخیره می‌شود.', en:'Change the admin login password from here to improve panel security. The new password is stored in the ADMIN environment variable in Cloudflare Workers.'},
gUsersPart2T:{fa:'آموزش ساخت کاربر', en:'How to create a user'},
gUsersPart2D_1:{fa:'از این بخش می‌توانید برای کاربر حجم، زمان و ریکوئست‌ها را مدیریت کنید. همچنین می‌توانید از پورت‌های TLS و None-TLS استفاده کنید.', en:'From this section you can manage the volume, time, and request limits for a user. You can also use TLS and None-TLS ports.'},
gUsersPart2D_2:{fa:'همان‌طور که در عکس دوم مشاهده می‌کنید، می‌توانید در این بخش از طریق سرور یا مخزن پنل، آی‌پی تمیز برای کاربر ست کنید. (<a class="inline-link" href="#guide-ipscan" onclick="showPage(\'guide-ipscan\')">آموزش استفاده از آی‌پی تمیز</a>)', en:'As shown in the second image, you can set a clean IP for the user either from a server or from the panel\'s pool. (<a class="inline-link" href="#guide-ipscan" onclick="showPage(\'guide-ipscan\')">Clean IP guide</a>)'},
gUsersPart2D_3:{fa:'فینگرپرینت روی حالت پیش‌فرض (در حال حاضر بهترین حالت Chrome است) تنظیم شده است.', en:'Fingerprint is set to the default mode (currently Chrome is the best option).'},
gUsersPart2D_4:{fa:'همچنین می‌توانید پروکسی آی‌پی جدا برای کاربر ست کنید. (<a class="inline-link" href="#guide-cdn" onclick="showPage(\'guide-cdn\')">آموزش استفاده از پروکسی آی‌پی</a>)', en:'You can also set a separate proxy IP for the user. (<a class="inline-link" href="#guide-cdn" onclick="showPage(\'guide-cdn\')">Proxy IP guide</a>)'},

gUsersPart3T:{fa:'آموزش دکمه‌ها', en:'Button guide'},
gUsersPart3D_1:{fa:'از طریق دکمه‌ی کپی سابسکریپشن به لینک اشتراک دسترسی پیدا کنید.', en:'Use the copy subscription button to get the subscription link.'},
gUsersPart3D_2:{fa:'از قسمت qrcode اشتراک می‌توانید اشتراک را به‌صورت QR کد وارد کلاینت خود کنید.', en:'Use the subscription QR code to add the subscription to your client via QR.'},
gUsersPart3D_3:{fa:'قسمت وضعیت سرویس برای ارائه به کاربر جهت دیدن وضعیت خودش است.', en:'The service status page can be shared with the user so they can check their own status.'},
gUsersPart3D_4:{fa:'قسمت لاگ اتصال، مشخصات کاربرانی که به سرویس متصل شده‌اند را نمایش می‌دهد؛ مانند آی‌پی، زمان اتصال و نوع ریکوئست (تست اتصال یا متصل‌شدن به سرویس).', en:'The connection log shows details of users connected to the service, such as IP, connection time, and request type (connection test or actual connection).'},
gUsersPart3D_5:{fa:'دکمه‌های زیر اسم سرویس به ترتیب از راست: توقف سرویس، ریست حجم سرویس کاربر، ریست زمان سرویس کاربر، ویرایش سرویس کاربر، ذخیره سرویس (برای جلوگیری از حذف خودکار) و حذف کامل سرویس.', en:'The buttons under the service name, from right to left: stop service, reset user volume, reset user time, edit user service, save service (prevents auto-deletion), and fully delete the service.'},
gUsersPart3D_6:{fa:'نکته: سرویس اصلی قابل حذف نیست، چرا که سرورهای نود روی سرویس اصلی اجرا خواهند شد.', en:'Note: the main service cannot be deleted, since node servers run on top of the main service.'}, 

    ovH1:{fa:'پنل مدیریتی سبک، سریع و رایگان<br>روی Cloudflare Workers', en:'A light, fast, free admin panel<br>on Cloudflare Workers'},
    ovLead:{fa:'NEXA Panel یک پنل مدیریتی است که کاملاً روی زیرساخت رایگان Cloudflare اجرا می‌شود؛ بدون نیاز به هیچ سرور جداگانه‌ای، نسخه‌ی اختصاصی خودتان را در چند دقیقه بالا می‌آورید.', en:"NEXA Panel is an admin panel that runs entirely on Cloudflare's free infrastructure — no separate server needed. Spin up your own instance in just a few minutes."},
    ovBtnDeploy:{fa:'نصب سریع پنل ←', en:'Quick Deploy ←'},
    ovBtnDemo:{fa:'وبسایت نکسا', en:'Nexa Website'},
    ovBtnTelegram:{fa:'کانال تلگرام', en:'Telegram Channel'},
    ovStat1n:{fa:'۰', en:'0'},
    ovStat1s:{fa:'سرور اختصاصی لازم', en:'Dedicated servers required'},
    ovStat2s:{fa:'لایسنس متن‌باز', en:'Open-source license'},
    ovStat3s:{fa:'پلن رایگان Cloudflare', en:'Cloudflare free tier'},
    ovImgAlt:{fa:'نمای داشبورد پنل نکسا', en:'NEXA Panel dashboard preview'},

    featSectionNum:{fa:'۰۲ / امکانات', en:'02 / Features'},
    featH2:{fa:'ویژگی‌ها', en:'Features'},
    feat1T:{fa:'استقرار فوری',en:'Instant Deployment'}, feat1D:{fa:'بدون نیاز به سرور اختصاصی؛ فقط چند دقیقه تا بالا آمدن پنل.',en:'No dedicated server needed — your panel is live in minutes.'},
    feat2T:{fa:'پلن رایگان',en:'Free Tier'}, feat2D:{fa:"روی زیرساخت رایگان Cloudflare Workers و D1 اجرا می‌شود.",en:"Runs entirely on Cloudflare Workers and D1's free tier."},
    feat3T:{fa:'نصب یک‌کلیکی',en:'One-Click Install'}, feat3D:{fa:'مناسب کاربران غیرفنی، بدون دستور خط فرمان.',en:'Great for non-technical users — no command line needed.'},
    feat4T:{fa:'نصب دستی',en:'Manual Install'}, feat4D:{fa:'کنترل کامل روی تنظیمات برای کاربران حرفه‌ای.',en:'Full control over configuration for advanced users.'},
    feat5T:{fa:'به‌روزرسانی خودکار',en:'Auto Updates'}, feat5D:{fa:'با Cron Trigger، پنل خودش را به‌صورت زمان‌بندی‌شده به‌روز می‌کند.',en:'A Cron Trigger keeps the panel updated on a schedule.'},
    feat6T:{fa:'کانفیگ VLESS',en:'VLESS Configs'}, feat6D:{fa:'ساخت خودکار کانفیگ با پروتکل VLESS.',en:'Automatic config generation using the VLESS protocol.'},
    feat7T:{fa:'TLS / None-TLS',en:'TLS / None-TLS'}, feat7D:{fa:'پشتیبانی از هر دو نوع پورت برای انعطاف بیشتر.',en:'Supports both port types for extra flexibility.'},
    feat8T:{fa:'مدیریت کاربران',en:'User Management'}, feat8D:{fa:'افزودن، ویرایش و نظارت بر کاربران پنل.',en:'Add, edit, and monitor panel users.'},
    feat9T:{fa:'بکاپ خودکار و دستی',en:'Auto & Manual Backup'}, feat9D:{fa:'پشتیبان‌گیری زمان‌بندی‌شده یا با یک کلیک.',en:'Scheduled backups or one-click backup anytime.'},
    feat10T:{fa:'پروکسی آی‌پی ثابت',en:'Static IP Proxy'}, feat10D:{fa:'مناسب کارهای عمومی؛ برای ترید و صرافی توصیه نمی‌شود.',en:'Good for general use; not recommended for trading or exchanges.'},
    feat11T:{fa:'اسکنر آی‌پی تمیز',en:'Clean IP Scanner'}, feat11D:{fa:'پیدا کردن آی‌پی‌های سالم و بدون فیلتر.',en:'Finds healthy, unblocked IP addresses.'},
    readyBadge:{fa:'ورود به پنل ', en:'Login To Panel'},
    readyTitle:{fa:'اکنون پنل شما آماده است', en:'Your panel is ready now'},
    readyAdminLabel:{fa:'آدرس پنل شما:', en:'Your panel address:'},
    qdSectionNum:{fa:'۰۳ / راه‌اندازی',en:'03 / Setup'},
    qdH2:{fa:'نصب سریع',en:'Quick Deploy'},
    qdP:{fa:'فقط کافیست وارد صفحه‌ی ساخت پنل شوید و مراحل را دنبال کنید؛ پنل شما روی دامنه‌ی رایگان Cloudflare بالا می‌آید.',en:'Just open the panel creation page and follow the steps — your panel goes live on a free Cloudflare domain.'},
    qdBtn:{fa:'رفتن به صفحه ساخت پنل ←',en:'Go to Deploy Page ←'},

    miSectionNum:{fa:'۰۴ / برای کاربران حرفه‌ای',en:'04 / For Advanced Users'},
    miH2:{fa:'نصب دستی',en:'Manual Install'},
    miP:{fa:'اگر ترجیح می‌دهید پنل را قدم‌به‌قدم و با کنترل کامل خودتان راه‌اندازی کنید، این پنج مرحله را دنبال کنید.',en:"If you'd rather set up the panel step by step with full control, follow these five steps."},
    step1T:{fa:'دانلود اسکریپت',en:'Download the Script'}, step1D:{fa:'فایل اسکریپت پنل نکسا را دانلود کنید.',en:'Download the NEXA Panel script file.'},
    step1Btn:{fa:'دانلود nexa.js ←',en:'Download nexa.js ←'},
    step2T:{fa:'ساخت Worker و آپلود کد',en:'Create a Worker & Upload the Code'}, step2D:{fa:'یک Worker جدید در Cloudflare بسازید و کد دانلودشده را روی آن آپلود کنید.',en:'Create a new Worker on Cloudflare and upload the downloaded code to it.'},
    step3T:{fa:'ساخت D1 و بایند کردن',en:'Create & Bind D1'},
    step3D_pre:{fa:'یک D1 Database بسازید و آن را با نام',en:'Create a D1 Database and bind it to your Worker under the name'},
    step3D_post:{fa:'به Worker خودتان بایند کنید',en:''},
    step4T:{fa:'تنظیم متغیر محیطی',en:'Set the Environment Variable'},
    step4D_pre:{fa:'متغیر محیطی',en:'Enter the environment variable'},
    step4D_post:{fa:'را در تنظیمات Worker وارد کنید',en:'in your Worker settings'},
    step5T:{fa:'تنظیم Cron Trigger',en:'Set the Cron Trigger'}, step5D:{fa:'یک Cron Trigger با مقدار زیر برای Worker تنظیم کنید:',en:'Set up a Cron Trigger for the Worker with the value below:'},

    guideCrumb:{fa:'راهنمای پنل',en:'Panel Guide'},
    guideDescLabel:{fa:'توضیحات',en:'Description'},

    gDashT:{fa:'داشبورد',en:'Dashboard'}, gDashSub:{fa:'نمای کلی از وضعیت مصرف، لینک اشتراک و مشخصات IP',en:'An overview of usage status, the subscription link, and IP details.'},
    gUsersT:{fa:'مدیریت کاربران',en:'User Management'}, gUsersSub:{fa:'افزودن، ویرایش و مشاهده‌ی وضعیت کاربران .',en:'Add, edit, and view the status of  users.'},
    gConnT:{fa:'آموزش اتصال',en:'Connection Guide'}, gConnSub:{fa:'راهنمای گام‌به‌گام اتصال برای اندروید، آیفون، ویندوز و مک.',en:'A step-by-step connection guide for Android, iPhone, Windows, and Mac.'}, gConnDesc:{fa:'این قسمت اموزش وارد کردن لینک سابسکریپشن را به کلاینت مربوطه میدهد',en:"This section teaches you how to enter the subscription link into the relevant client."},
    gNodeT:{fa:'سرور نود',en:'Node Server'}, gNodeSub:{fa:'مدیریت نودهای متصل به پنل.',en:'Manage the nodes connected to the panel.'}, gNodeDesc:{fa:'در این قسمت میتوانید به سرور های نود سرویس اصلی وصل شوید این نود ها بر پایه پورت های  tls کلادفلر میباشد که در قسمت ادرس به جای قرار گرفتن ایپی تمیز ادرس ورکر شما قرار میگیرد (حالت خودکار )',en:"In this section, you can connect to the main service node servers. These nodes are based on Cloudflare's TLS ports, which in the address section will be your worker address instead of the clean IP (automatic mode)."},
    gIpT:{fa:'اسکنر IP تمیز',en:'Clean IP Scanner'}, gIpSub:{fa:'پیدا کردن سریع‌ترین آی‌پی‌های تمیز کلودفلر برای شبکه‌ی شما.',en:'Find the fastest clean Cloudflare IPs for your network.'}, gIpDesc:{fa:'حالت اول: اسکن با اینترنت شما — در این حالت مطابق اینترنت و ISP ارائه‌دهنده اینترنت شما اسکن انجام می‌شود و بهترین آی‌پی‌ها برای شما یافت خواهد شد.<br>حالت دوم: دریافت آی‌پی تمیز از سرور — در این حالت آی‌پی‌های اسکن‌شده از قبل، از طریق سرور ما به دست شما می‌رسد.',en:"Mode 1: Scan using your internet — the scan runs based on your ISP's network to find the best IPs for you.<br>Mode 2: Get clean IPs from server — pre-scanned clean IPs are delivered to you from our server."},
    gCdnT:{fa:'پروکسی CDN',en:'CDN Proxy'}, gCdnSub:{fa:'تنظیمات دسترسی CDN کلودفلر و PROXYIP.',en:'Settings for Cloudflare CDN access and PROXYIP.'}, gCdnDesc:{fa:'اموزش این قسمت به زودی در دسترس قرار خواهد گرفت',en:"Coming Soon ..."},
    gLogsT:{fa:'لاگ فعالیت',en:'Activity Log'}, gLogsSub:{fa:'نمایش لاگ پنل شما',en:'Show Your Panel Logs'}, gLogsDesc:{fa:'در این بهش میتوانید لاگ پنل خود را مشاهده کنید همچنین میتوانید با تنظیم توکن ربات تلگرام لاگ پنل خود را از طریق تلگرام دریافت کنید.',en:"In this page, you can view your log panel. You can also receive your log panel via Telegram by setting the Telegram bot token."},
    gSetT:{fa:'تنظیمات پنل',en:'Panel Settings'}, gSetSub:{fa:'به‌روزرسانی، مسیر صفحات، نام‌گذاری کانفیگ و قطع اضطراری سرویس‌ها.',en:'Updates, page routes, config naming, and emergency service shutoff.'},
    linksSectionNum:{fa:'۰۶ / منابع',en:'06 / Resources'}, linksH2:{fa:'لینک های کاربردی',en:'Useful Links'},
    linkWebsite:{fa:'وب‌سایت',en:'Website'}, linkDeploy:{fa:'صفحه نصب',en:'Deploy Page'}, linkTelegram:{fa:'کانال تلگرام',en:'Telegram Channel'}, linkYoutube:{fa:'یوتیوب',en:'YouTube'}, linkGithub:{fa:'مخزن گیت‌هاب',en:'GitHub Repo'}, linkRelease:{fa:'آخرین نسخه',en:'Latest Release'},

    supportSectionNum:{fa:'۰۷ / حمایت',en:'07 / Support'}, supportH2:{fa:'حمایت مالی',en:'Support Us'},
    supportP:{fa:'اگر این پروژه برایتان مفید بوده، می‌توانید با ارسال رمزارز از پروژه حمایت کنید 🙏',en:'If this project has been useful to you, you can support it with a crypto donation 🙏'},
    thCurrency:{fa:'ارز',en:'Currency'}, thWallet:{fa:'آدرس کیف پول',en:'Wallet Address'},
    copyBtn:{fa:'کپی',en:'Copy'}, copiedBtn:{fa:'کپی شد ✓',en:'Copied ✓'},

    licenseSectionNum:{fa:'۰۸ / قانونی',en:'08 / Legal'}, licenseH2:{fa:'لایسنس',en:'License'},
    licenseP_pre:{fa:'این پروژه تحت لایسنس',en:'This project is released under the'},
    licenseP_mid:{fa:'منتشر شده است. برای جزئیات بیشتر فایل',en:'license. For more details, see the'},
    licenseP_or:{fa:'یا صفحه‌ی رسمی',en:'file or the official'},
    licenseP_link:{fa:'MIT License',en:'MIT License'},
    licenseP_end:{fa:'را ببینید',en:'page'},

    footer1:{fa:'ساخته شده توسط تیم NEXA',en:'Built by the NEXA Team'},
    footer2:{fa:'مستندات',en:'Documentation'},

    relFetching:{fa:'در حال دریافت نسخه…',en:'fetching version…'},
    relTagPrefix:{fa:'ریلیز ',en:'Release '},
    relNoRelease:{fa:'هنوز ریلیزی منتشر نشده',en:'No release published yet'},
    relViewRepo:{fa:'مشاهده مخزن گیت‌هاب',en:'View GitHub repo'},
    relSourceDownload:{fa:'دانلود سورس ریلیز ',en:'Download release source '}
  };

  let currentLang = localStorage.getItem('nexa-lang') || 'fa';

  function t(key){
    const entry = translations[key];
    if(!entry) return '';
    return entry[currentLang] !== undefined ? entry[currentLang] : entry.fa;
  }

  function applyLang(lang){
    currentLang = lang;
    document.documentElement.lang = lang === 'fa' ? 'fa' : 'en';
    document.documentElement.dir = lang === 'fa' ? 'rtl' : 'ltr';
    document.documentElement.setAttribute('data-lang', lang);
    localStorage.setItem('nexa-lang', lang);

    document.title = t('pageTitle');
    const descMeta = document.getElementById('pageDesc');
    if(descMeta) descMeta.setAttribute('content', t('pageDesc'));

    document.querySelectorAll('[data-i18n]').forEach(el => {
      el.textContent = t(el.getAttribute('data-i18n'));
    });
    document.querySelectorAll('[data-i18n-html]').forEach(el => {
      el.innerHTML = t(el.getAttribute('data-i18n-html'));
    });
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
      el.setAttribute('placeholder', t(el.getAttribute('data-i18n-placeholder')));
    });
    document.querySelectorAll('[data-i18n-title]').forEach(el => {
      el.setAttribute('title', t(el.getAttribute('data-i18n-title')));
    });
    document.querySelectorAll('[data-i18n-alt]').forEach(el => {
      el.setAttribute('alt', t(el.getAttribute('data-i18n-alt')));
    });

    // re-apply nav-group-btn text (they contain a chevron svg appended after text)
    document.querySelectorAll('.nav-group-btn').forEach(btn => {
      const key = btn.getAttribute('data-i18n');
      const svg = btn.querySelector('svg');
      btn.textContent = t(key);
      if(svg) btn.appendChild(svg);
    });

    langToggle.textContent = lang === 'fa' ? 'EN' : 'فا';
    hamburgerBtn.setAttribute('title', document.body.classList.contains('menu-open') ? t('menuCloseTitle') : t('menuOpenTitle'));
    renderRelease();
  }

  /* ===== Theme ===== */
  const root = document.documentElement;
  const themeToggle = document.getElementById('themeToggle');
  const themeIcon = document.getElementById('themeIcon');
  function applyTheme(mode){
    root.setAttribute('data-theme', mode);
    themeIcon.innerHTML = mode === 'dark' ? '<use href="#icon-sun"/>' : '<use href="#icon-moon"/>';
    themeToggle.title = mode === 'dark' ? translations.themeToLight[currentLang] : translations.themeToDark[currentLang];
    localStorage.setItem('nexa-theme', mode);
  }
  const savedTheme = localStorage.getItem('nexa-theme');
  const prefersLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
  applyTheme(savedTheme || (prefersLight ? 'light' : 'dark'));
  themeToggle.addEventListener('click', () => {
    applyTheme(root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
  });

  /* ===== Language toggle ===== */
  const langToggle = document.getElementById('langToggle');
  langToggle.addEventListener('click', () => {
    applyLang(currentLang === 'fa' ? 'en' : 'fa');
  });

  /* ===== Hamburger / mobile menu ===== */
  const hamburgerBtn = document.getElementById('hamburgerBtn');
  const hamburgerIcon = document.getElementById('hamburgerIcon');

  function closeMobileMenu(){
    document.body.classList.remove('menu-open');
    hamburgerBtn.setAttribute('aria-expanded', 'false');
    hamburgerIcon.innerHTML = '<use href="#icon-menu"/>';
    hamburgerBtn.title = t('menuOpenTitle');
    navGroups.forEach(g => g.classList.remove('open'));
  }

  hamburgerBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    const isOpen = document.body.classList.toggle('menu-open');
    hamburgerBtn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    hamburgerIcon.innerHTML = isOpen ? '<use href="#icon-close"/>' : '<use href="#icon-menu"/>';
    hamburgerBtn.title = isOpen ? t('menuCloseTitle') : t('menuOpenTitle');
    if(!isOpen){ navGroups.forEach(g => g.classList.remove('open')); }
  });
  window.addEventListener('resize', () => {
    if(window.innerWidth > 880 && document.body.classList.contains('menu-open')){
      closeMobileMenu();
    }
  });
  document.addEventListener('keydown', (e) => {
    if(e.key === 'Escape' && document.body.classList.contains('menu-open')){
      closeMobileMenu();
    }
  });

  /* ===== Top nav groups (dropdown / accordion) ===== */
  const navGroups = Array.from(document.querySelectorAll('.nav-group'));
  const DESKTOP_MQ = window.matchMedia('(min-width:881px)');
  let closeTimer = null;

  navGroups.forEach(group => {
    const btn = group.querySelector('.nav-group-btn');

    // Click: used on mobile (accordion) and as a fallback on desktop
    // (e.g. touch-enabled laptops where hover never fires).
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const isOpen = group.classList.contains('open');
      navGroups.forEach(g => g.classList.remove('open'));
      if(!isOpen) group.classList.add('open');
    });

    // Hover: on desktop, opening/keeping-open is driven from JS (not just
    // the CSS :hover rule) so the menu reliably stays open while the
    // pointer moves from the button down into the dropdown, with no need
    // to click anything.
    group.addEventListener('mouseenter', () => {
      if(!DESKTOP_MQ.matches) return;
      clearTimeout(closeTimer);
      navGroups.forEach(g => { if(g !== group) g.classList.remove('open'); });
      group.classList.add('open');
    });
    group.addEventListener('mouseleave', () => {
      if(!DESKTOP_MQ.matches) return;
      closeTimer = setTimeout(() => group.classList.remove('open'), 150);
    });
  });

  document.addEventListener('click', (e) => {
    navGroups.forEach(g => g.classList.remove('open'));
    // Tapping anywhere outside the open mobile menu closes it too.
    if(document.body.classList.contains('menu-open') && !e.target.closest('#topNav') && !e.target.closest('#hamburgerBtn')){
      closeMobileMenu();
    }
  });

  /* ===== Single-page navigation: only the selected item is shown ===== */
  const links = Array.from(document.querySelectorAll('.nav-dropdown a'));
  const pages = Array.from(document.querySelectorAll('main .page'));
  const pageIds = pages.map(p => p.id);

  function showPage(id, opts){
    opts = opts || {};
    if(!pageIds.includes(id)) id = pageIds[0];
    pages.forEach(p => p.classList.toggle('is-active', p.id === id));
    links.forEach(l => l.classList.toggle('active', l.getAttribute('href') === '#' + id));
    if(!opts.silent){
      history.pushState(null, '', '#' + id);
    }
    window.scrollTo({ top: 0, behavior: 'auto' });
  }

  links.forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      showPage(link.getAttribute('href').slice(1));
      closeMobileMenu();
    });
  });

  window.addEventListener('popstate', () => {
    const id = location.hash.replace('#', '');
    showPage(id || pageIds[0], { silent: true });
  });

  showPage(location.hash.replace('#', '') || pageIds[0], { silent: true });

  /* ===== Header search (its own results dropdown) ===== */
  const searchInput = document.getElementById('searchInput');
  const searchResults = document.getElementById('searchResults');
  const searchBox = document.querySelector('.search-box');

  function groupLabelFor(link){
    const group = link.closest('.nav-group');
    const key = group ? group.querySelector('.nav-group-btn').getAttribute('data-i18n') : '';
    return key ? t(key) : '';
  }

  function renderSearch(query){
    const q = query.trim().toLowerCase();
    if(q === ''){
      searchResults.classList.remove('show');
      searchResults.innerHTML = '';
      return;
    }
    const matches = links.filter(link => {
      const haystack = (link.textContent + ' ' + (link.dataset.text||'')).toLowerCase();
      return haystack.includes(q);
    }).slice(0, 8);

    if(matches.length === 0){
      searchResults.innerHTML = '<div class="no-match">' + t('searchNoMatch') + '</div>';
    } else {
      searchResults.innerHTML = '';
      matches.forEach(link => {
        const a = document.createElement('a');
        a.href = link.getAttribute('href');
        const titleEl = document.createElement('div');
        titleEl.className = 'sr-title';
        titleEl.textContent = link.textContent.trim();
        const groupEl = document.createElement('div');
        groupEl.className = 'sr-group';
        groupEl.textContent = groupLabelFor(link);
        a.appendChild(titleEl);
        a.appendChild(groupEl);
        a.addEventListener('click', (e) => {
          e.preventDefault();
          showPage(link.getAttribute('href').slice(1));
          searchInput.value = '';
          searchResults.classList.remove('show');
          searchResults.innerHTML = '';
        });
        searchResults.appendChild(a);
      });
    }
    searchResults.classList.add('show');
  }

  searchInput.addEventListener('input', () => renderSearch(searchInput.value));
  searchInput.addEventListener('focus', () => { if(searchInput.value.trim() !== '') renderSearch(searchInput.value); });
  searchInput.addEventListener('keydown', (e) => {
    if(e.key === 'Enter'){
      const first = searchResults.querySelector('a');
      if(first) first.click();
    }
  });
  document.addEventListener('click', (e) => {
    if(!searchBox.contains(e.target)){
      searchResults.classList.remove('show');
    }
  });

  /* ===== Release fetch (language-aware rendering) ===== */
  const REPO = 'farzadqavidel/nexa-panel';
  let releaseState = { status: 'loading' };

  function renderRelease(){
    const brandTag = document.getElementById('brandTag');
    const linkCard = document.getElementById('releaseLinkCard');
    const linkSub = document.getElementById('releaseLinkSub');
    const dlBtn = document.getElementById('downloadScriptBtn');

    if(releaseState.status === 'loading'){
      if(brandTag) brandTag.textContent = 'docs · ' + t('relFetching');
      if(linkSub) linkSub.textContent = t('relFetching');
      return;
    }
    if(releaseState.status === 'error'){
      if(brandTag) brandTag.textContent = 'docs · dev';
      if(linkSub) linkSub.textContent = t('relViewRepo');
      if(linkCard) linkCard.href = 'https://github.com/' + REPO + '/releases';
      return;
    }
    const d = releaseState.data;
    if(brandTag) brandTag.textContent = 'docs · ' + d.tag;
    const locale = currentLang === 'fa' ? 'fa-IR' : 'en-US';
    if(linkSub) linkSub.textContent = d.tag + (d.publishedAt ? ' · ' + new Date(d.publishedAt).toLocaleDateString(locale) : '');
    if(linkCard) linkCard.href = d.url;
    if(dlBtn){
      if(d.scriptAssetUrl){
        dlBtn.href = d.scriptAssetUrl;
        dlBtn.textContent = (currentLang === 'fa' ? 'دانلود ' : 'Download ') + d.scriptAssetName + ' ←';
      } else {
        dlBtn.href = d.zipUrl || dlBtn.href;
        dlBtn.textContent = t('relSourceDownload') + d.tag + ' ←';
      }
    }
  }
  (async function loadRelease(){
    try{
      const res = await fetch('https://api.github.com/repos/' + REPO + '/releases/latest');
      if(!res.ok) throw new Error('no-release');
      const data = await res.json();
      const tag = data.tag_name || data.name;
      if(!tag) throw new Error('no-tag');
      const scriptAsset = (data.assets || []).find(a => /\.js$/i.test(a.name)) || (data.assets || [])[0];
      releaseState = {
        status: 'ok',
        data: {
          tag: tag,
          url: data.html_url,
          publishedAt: data.published_at,
          scriptAssetUrl: scriptAsset ? scriptAsset.browser_download_url : null,
          scriptAssetName: scriptAsset ? scriptAsset.name : null,
          zipUrl: data.zipball_url
        }
      };
    }catch(e){
      releaseState = { status: 'error' };
    }
    renderRelease();
  })();

  document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const text = btn.dataset.copy;
      try{
        await navigator.clipboard.writeText(text);
        const original = btn.textContent;
        btn.textContent = t('copiedBtn');
        setTimeout(() => btn.textContent = original, 1500);
      }catch(err){}
    });
  });

  /* ===== Init language (applies saved/default language on load) ===== */
  applyLang(currentLang);
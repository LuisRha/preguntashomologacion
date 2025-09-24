// === Selectores de la UI ===
const searchInput = document.getElementById('searchInput');
const searchButton = document.getElementById('searchButton');
const clearButton = document.getElementById('clearButton');
const results = document.getElementById('results');

// === Banco de 100 preguntas (primer cuestionario que ya cargamos antes) ===
const baseQuestions = [
  { question: "¿Qué política de seguridad HTTP fuerza el uso de HTTPS?", correctAnswer: "Strict-Transport-Security (HSTS)" },
  { question: "¿Cuál es la principal diferencia entre un hacker ético y un cracker?", correctAnswer: "Los hackers éticos tienen autorización; los crackers actúan ilegalmente." },
  { question: "¿Qué tipo de dirección MAC representa un broadcast en una red Ethernet?", correctAnswer: "FF:FF:FF:FF:FF:FF" },
  { question: "¿Qué tipo de ataque busca borrar huellas digitales en un sistema comprometido?", correctAnswer: "Anti-forense" },
  { question: "¿Cuál es una ventaja de aplicar inteligencia de amenazas en una organización?", correctAnswer: "Mejorar la capacidad de prevenir y mitigar ciberataques." },
  { question: "¿Qué requisito debe cumplir una transferencia internacional de datos según la LOPDP?", correctAnswer: "Que el país receptor tenga nivel adecuado de protección." },
  { question: "¿Cuál es el objetivo principal de la informática forense?", correctAnswer: "Identificar, preservar, analizar y presentar evidencia digital." },
  { question: "¿Qué técnica recupera archivos eliminados?", correctAnswer: "File carving" },
  { question: "¿Qué hash es estándar en verificaciones de integridad forense?", correctAnswer: "SHA-256" },
  { question: "¿Qué cabecera HTTP ayuda a prevenir el sniffing de MIME types?", correctAnswer: "X-Content-Type-Options: nosniff" },
  { question: "¿Qué significa el principio de “mínimo privilegio” en sistemas de información?", correctAnswer: "Los usuarios solo deben tener los permisos necesarios para sus funciones." },
  { question: "¿Cuál es una característica clave de una herramienta forense confiable?", correctAnswer: "Debe ser capaz de eliminar malware." },
  { question: "Según la Ley Orgánica de Protección de Datos Personales (LOPDP) de Ecuador, ¿qué principio obliga a las empresas a solicitar consentimiento explícito antes de tratar datos personales?", correctAnswer: "Principio de consentimiento informado." },
  { question: "¿Qué capa del modelo OSI se encarga del enrutamiento de paquetes?", correctAnswer: "Capa 3 (Red)" },
  { question: "¿Qué artículo de la Ley de Comercio Electrónico regula la publicidad digital?", correctAnswer: "Art. 10 (veracidad y no engaño)." },
  { question: "¿Cuál es el propósito de una prueba de penetración (pentest)?", correctAnswer: "Identificar vulnerabilidades explotables en un sistema." },
  { question: "¿Qué estándar clasifica el nivel de impacto de una vulnerabilidad (CVSS)?", correctAnswer: "Escala del 0 al 10" },
  { question: "¿Cuál de las siguientes topologías de red es más tolerante a fallos?", correctAnswer: "Malla" },
  { question: "¿Qué protocolo opera en la capa de transporte y es orientado a conexión?", correctAnswer: "TCP" },
  { question: "¿Qué ataque intercepta la comunicación entre dos partes sin su conocimiento?", correctAnswer: "Man-in-the-Middle (MITM)" },
  { question: "¿Qué herramienta automatiza ataques de fuerza bruta a servicios de red?", correctAnswer: "Hydra" },
  { question: "¿Qué base de datos pública registra vulnerabilidades conocidas?", correctAnswer: "CVE (Common Vulnerabilities and Exposures)" },
  { question: "¿Qué técnica correlaciona eventos de seguridad para identificar patrones complejos?", correctAnswer: "SIEM" },
  { question: "¿Qué es un “zero-day-exploit”?", correctAnswer: "Una vulnerabilidad desconocida por el fabricante y sin parches disponibles." },
  { question: "¿Qué protocolo cifra la comunicación web para mayor seguridad?", correctAnswer: "HTTPS" },
  { question: "¿Qué institución ecuatoriana supervisa el cumplimiento de la LOPDP?", correctAnswer: "Autoridad de Protección de Datos Personales (APDP)." },
  { question: "¿Cuál es la Ley del Ecuador que regula la protección de datos personales en entornos digitales?", correctAnswer: "Ley Orgánica de Protección de Datos Personales (LOPDP)." },
  { question: "¿Cuál de los siguientes es un principio clave para implementar seguridad en una aplicación web?", correctAnswer: "Validar y sanitizar todas las entradas del usuario." },
  { question: "¿Qué estándar garantiza la admisibilidad legal de evidencia digital?", correctAnswer: "Norma ISO 27037" },
  { question: "¿Qué modelo describe las etapas de un ciberataque para mejorar la detección y prevención?", correctAnswer: "MITRE ATT&CK." },
  { question: "¿Qué protocolo debe utilizarse para asegurar la transferencia de datos entre cliente y servidor en una aplicación web?", correctAnswer: "HTTPS." },
  { question: "¿Qué tipo de informe contiene detalles técnicos sobre una campaña de malware específica?", correctAnswer: "Threat Report" },
  { question: "¿Qué dispositivo amplifica una señal para extender el alcance de una red?", correctAnswer: "Repetidor" },
  { question: "¿Qué estándar se usa para certificados digitales en la web?", correctAnswer: "X.509" },
  { question: "¿Qué tipo de ataque explota vulnerabilidades en consultas SQL para acceder a bases de datos?", correctAnswer: "SQL Injection." },
  { question: "¿Qué tipo de licencia Creative Commons permite uso comercial sin modificaciones?", correctAnswer: "CC BY-ND." },
  { question: "¿Cuál de los siguientes dispositivos opera en la capa 2 (enlace de datos) del modelo OSI?", correctAnswer: "Switch." },
  { question: "¿Qué herramienta permite analizar el tráfico de red en tiempo real?", correctAnswer: "Wireshark" },
  { question: "¿Qué tipo de inteligencia se centra en indicadores técnicos como direcciones IP y hashes de malware?", correctAnswer: "Inteligencia táctica" },
  { question: "¿Qué técnica se usa para engañar a los usuarios y robar credenciales mediante páginas falsas?", correctAnswer: "Phishing" },
  { question: "¿Qué comando muestra la tabla de enrutamiento en un sistema Windows?", correctAnswer: "route print" },
  { question: "¿Qué característica debe tener un sistema de autenticación robusto en una aplicación web?", correctAnswer: "Aplicar hash a las contraseñas almacenadas." },
  { question: "¿Qué herramienta se usa para analizar vulnerabilidades en aplicaciones web?", correctAnswer: "OWASP ZAP" },
  { question: "¿Qué componente de seguridad web valida y filtra el tráfico entrante / saliente en un servidor?", correctAnswer: "WAF (Web Application Firewall)." },
  { question: "¿Qué estándar define las redes inalámbricas WiFi?", correctAnswer: "IEEE 802.11" },
  { question: "¿Qué tipo de ataque consiste en inyectar código malicioso en una página web para robar información de usuarios?", correctAnswer: "Cross-Site-Scripting (XSS)." },
  { question: "¿Qué protocolo de la capa de red es responsable de asignar direcciones IP dinámicas en una red?", correctAnswer: "DHCP." },
  { question: "¿Qué modelo analiza amenazas mediante cuatro vértices (adversario, capacidad, infraestructura, víctima)?", correctAnswer: "Diamond Model" },
  { question: "¿Qué herramienta se utiliza comúnmente para analizar el tráfico de red y capturar paquetes?", correctAnswer: "Wireshark." },
  { question: "¿Qué sistema de archivos es común en dispositivos móviles Android?", correctAnswer: "EXT4" },
  { question: "¿Cuál es la sanción por incumplir la LOPDP en Ecuador?", correctAnswer: "Multas de hasta 1% de los ingresos anuales de la empresa." },
  { question: "¿Qué técnica identifica patrones de actividad maliciosa en logs?", correctAnswer: "Análisis de línea de tiempo (Timeline Analysis)" },
  { question: "¿Qué herramienta de OSINT rastrea información en redes sociales?", correctAnswer: "Maltego" },
  { question: "¿Cuál es la principal función de los headers HTTP de seguridad como “Content-Security-Policy” (CSP)?", correctAnswer: "Restringir la ejecución de recursos no confiables (scripts, iframes, etc)." },
  { question: "¿Qué tipo de dirección IP es 192.168.1.1?", correctAnswer: "Privada" },
  { question: "¿Qué delito del COIP sanciona el acceso no autorizado a sistemas informáticos?", correctAnswer: "Art. 234 (Hacking)." },
  { question: "¿Qué vulnerabilidad explota la confianza de un sitio web en el navegador del usuario?", correctAnswer: "CSRF" },
  { question: "¿Qué protocolo de la capa de aplicación es utilizado para la transferencia segura de archivos?", correctAnswer: "SFTP" },
  { question: "¿Qué tipo de red tiene direccionalidad en sus conexiones?", correctAnswer: "Red dirigida." },
  { question: "¿Según el COESC, ¿qué no está protegido por derechos de autor?", correctAnswer: "Las ideas no expresadas materialmente." },
  { question: "¿Qué protocolo resuelve nombres de dominio a direcciones IP?", correctAnswer: "DNS" },
  { question: "¿Qué término describe la reconstrucción de eventos a partir de datos digitales?", correctAnswer: "Reconstrucción forense digital" },
  { question: "¿Qué método HTTP es seguro para enviar datos sensibles como por ejemplo contraseñas?", correctAnswer: "POST" },
  { question: "¿Qué es un IoC (Indicador de Compromiso)?", correctAnswer: "Una evidencia observable de que una brecha de seguridad ha ocurrido." },
  { question: "¿Qué fase del Cyber Kill Chain implica el despliegue de malware?", correctAnswer: "Delivery" },
  { question: "¿Qué tratado internacional contra la ciberdelincuencia ratificó Ecuador en 2019?", correctAnswer: "Tratado de Marrakech." },
  { question: "¿Qué técnica ayuda a prevenir el secuestro de sesiones (Session Hijacking)?", correctAnswer: "Regenerar el ID de sesión tras autenticación." },
  { question: "¿Qué función tiene un hash criptográfico en informática forense?", correctAnswer: "Verificar la integridad de la evidencia digital." },
  { question: "¿Qué mecanismo permite verificar la identidad de un sitio web mediante un certificado digital?", correctAnswer: "SSL/TLS." },
  { question: "¿Qué tipo de clave es necesaria para el cifrado asimétrico?", correctAnswer: "Ambas (clave pública y privada)" },
  { question: "¿Qué componente de inteligencia se enfoca en predicciones a largo plazo?", correctAnswer: "Inteligencia estratégica" },
  { question: "¿Qué dispositivo conecta redes con diferentes protocolos o arquitecturas?", correctAnswer: "Gateway" },
  { question: "¿Qué comando se usa para diagnosticar la ruta que sigue un paquete hacia un destino?", correctAnswer: "Traceroute (tracert en Windows)" },
  { question: "¿Qué herramienta analiza imágenes de memoria RAM?", correctAnswer: "Volatility" },
  { question: "¿Qué principio forense asegura que los datos originales no sean alterados durante la investigación?", correctAnswer: "Cadena de custodia." },
  { question: "¿Qué herramienta de OSINT permite recopilar información sobre dominios y direcciones IP asociadas a amenazas?", correctAnswer: "VirusTotal." },
  { question: "¿Cuál es el primer paso en una investigación forense digital?", correctAnswer: "Adquisición y preservación de la evidencia." },
  { question: "¿Qué tipo de ataque consiste en inundar una red con solicitudes falsas para denegar el servicio a usuarios legítimos?", correctAnswer: "DDoS (Ataque de denegación de servicio)." },
  { question: "¿Qué licencia de software, reconocida en el Ecuador bajo el COESC, permite el uso y modificación libre pero exige compartir las mejoras bajo la misma licencia?", correctAnswer: "Licencia GPL (Software Libre)." },
  { question: "¿Qué tipo de red cubre un área geográfica extensa, como una ciudad?", correctAnswer: "MAN" },
  { question: "¿Qué principio evita la modificación de evidencia durante su análisis?", correctAnswer: "Cadena de custodia" },
  { question: "¿Qué herramienta forense es de código abierto?", correctAnswer: "Autopsy" },
  { question: "¿Qué pena puede imponerse por difundir pornografía infantil en línea según el COIP?", correctAnswer: "Hasta 13 años de prisión." },
  { question: "¿Qué framework ayuda a clasificar y compartir indicadores de compromiso (IOCs)?", correctAnswer: "STIX/TAXII" },
  { question: "¿Qué artículo de la Constitución ecuatoriana garantiza el derecho a la protección de datos?", correctAnswer: "Art. 66.26." },
  { question: "¿Qué delito tipifica el COIP por suplantar identidad digital?", correctAnswer: "Art. 177 (Fraude informático)." },
  { question: "¿Qué herramienta analiza dominios maliciosos y direcciones IP?", correctAnswer: "VirusTotal" },
  { question: "¿Qué protocolo ayuda a compartir automáticamente indicadores de amenaza entre organizaciones?", correctAnswer: "TAXII" },
  { question: "¿Qué herramienta permite escribir reglas para identificar muestras de malware?", correctAnswer: "YARA" },
  { question: "¿Qué mecanismo almacena información del usuario en el navegador para autenticación?", correctAnswer: "Cookies" },
  { question: "¿Qué objetivo principal tiene el Convenio de Budapest, ratificado por el Ecuador en 2019?", correctAnswer: "Armonizar leyes contra la ciberdelincuencia y facilitar la cooperación entre países." },
  { question: "¿Qué representa un nodo en una red de datos?", correctAnswer: "Un punto o entidad que se conecta con otros nodos." },
  { question: "¿Qué protocolo se utiliza para enviar correos electrónicos desde un cliente a un servidor?", correctAnswer: "SMTP" },
  { question: "¿Qué herramienta ayuda a detectar puertos abiertos en un servidor web?", correctAnswer: "Nmap" },
  { question: "¿Qué entidad regula el espectro radioeléctrico y servicios de internet en Ecuador?", correctAnswer: "ARCOTEL." },
  { question: "¿Cuál es el objetivo principal de explotar una vulnerabilidad de inyección de SQL?", correctAnswer: "Manipular consultas a bases de datos." },
  { question: "¿Qué herramienta analiza tráfico de red en investigaciones forenses?", correctAnswer: "Wireshark" },
  { question: "¿Qué ley protege a los consumidores en compras online en Ecuador?", correctAnswer: "Ley Orgánica de Defensa del Consumidor." },
  { question: "¿Cuál es una medida efectiva contra ataques de Cross-Site-Scripting (XSS)?", correctAnswer: "Validar y escapar el contenido de entrada del usuario." },
  { question: "¿Qué principio de seguridad limita los permisos de usuarios y sistemas?", correctAnswer: "Principio de Mínimo Privilegio" }
];

// === Nuevas preguntas (las que me enviaste ahora). Las añadimos TODAS y deduplicamos ===
const newQuestions = [
  { question: "¿Qué ley regula el uso de cookies y rastreo web en Ecuador?", correctAnswer: "LOPDP (consentimiento informado)." },
  { question: "¿Cuál es la sanción por incumplir la LOPDP en Ecuador?", correctAnswer: "Multas de hasta 1% de los ingresos anuales de la empresa." },
  { question: "¿Qué significa el principio de “mínimo privilegio” en sistemas de información?", correctAnswer: "Los usuarios solo deben tener los permisos necesarios para sus funciones." },
  { question: "¿Qué término describe malware que evade análisis mediante técnicas de ofuscación?", correctAnswer: "Polimórfico" },
  { question: "¿Qué ley protege a los consumidores en compras online en Ecuador?", correctAnswer: "Ley Orgánica de Defensa del Consumidor." },
  { question: "¿Qué tipo de cable de red se usa comúnmente en conexiones Ethernet?", correctAnswer: "UTP (Par trenzado no blindado)" },
  { question: "¿Qué modelo analiza amenazas mediante cuatro vértices (adversario, capacidad, infraestructura, víctima)?", correctAnswer: "Diamond Model" },
  { question: "¿Qué mecanismo almacena información del usuario en el navegador para autenticación?", correctAnswer: "Cookies" },
  { question: "¿Qué estándar define las redes inalámbricas WiFi?", correctAnswer: "IEEE 802.11" },
  { question: "¿Qué herramienta se usa para verificar la conectividad entre dos hosts en una red?", correctAnswer: "Ping" },
  { question: "¿Qué herramienta automatiza ataques de fuerza bruta a servicios de red?", correctAnswer: "Hydra" },
  { question: "¿Cuál es la técnica que consiste en suplantar la identidad de una entidad confiable para obtener credenciales o información?", correctAnswer: "Phishing." },
  { question: "¿Qué técnica ayuda a prevenir el secuestro de sesiones (Session Hijacking)?", correctAnswer: "Regenerar el ID de sesión tras autenticación." },
  { question: "¿Qué tipo de inteligencia se centra en indicadores técnicos como direcciones IP y hashes de malware?", correctAnswer: "Inteligencia táctica" },
  { question: "¿Qué tipo de ataque permite ejecutar scripts maliciosos en el navegador de la víctima?", correctAnswer: "Cross-Site Scripting (XSS)" },
  { question: "¿Cuál de los siguientes es un objetivo principal de la inteligencia de ciberseguridad?", correctAnswer: "Anticipar, detectar y responder a amenazas cibernéticas de manera proactiva." },
  { question: "¿Cuál es una característica clave de una herramienta forense confiable?", correctAnswer: "Debe ser capaz de eliminar malware." },
  { question: "¿Qué estándar garantiza la admisibilidad legal de evidencia digital?", correctAnswer: "Norma ISO 27037" },
  { question: "¿Qué cabecera HTTP ayuda a prevenir ataques XSS?", correctAnswer: "Content-Security-Policy (CSP)" },
  { question: "¿Qué comando muestra la tabla de enrutamiento en un sistema Windows?", correctAnswer: "route print" },
  { question: "¿Qué herramienta forense es de código abierto?", correctAnswer: "Autopsy" },
  { question: "¿Cuál es una medida efectiva contra ataques de Cross-Site-Scripting (XSS)?", correctAnswer: "Validar y escapar el contenido de entrada del usuario." },
  { question: "¿Qué tipo de autenticación requiere múltiples factores de verificación?", correctAnswer: "MFA (Multi-Factor Authentication)" },
  { question: "¿Qué herramienta se usa comúnmente para escaneo de puertos?", correctAnswer: "Nmap." },
  { question: "¿Qué técnica recupera archivos eliminados?", correctAnswer: "File carving" },
  { question: "¿Qué técnica simula ataques para evaluar defensas sin daño real?", correctAnswer: "Red Teaming" },
  { question: "¿Qué protocolo de la capa de aplicación es utilizado para la transferencia segura de archivos?", correctAnswer: "SFTP" },
  { question: "¿Qué es el Hacking Ético?", correctAnswer: "Evaluar de forma autorizada la seguridad de un sistema." },
  { question: "¿Qué tipo de ataque consiste en suplantar una dirección IP legítima?", correctAnswer: "IP Spoofing" },
  { question: "¿Qué componente almacena datos temporales en un sistema informático?", correctAnswer: "RAM" },
  { question: "¿Qué tecnología permite dividir una red física en múltiples redes lógicas?", correctAnswer: "VLAN." },
  { question: "¿Qué tipo de evidencia digital es volátil y se pierde al apagar el sistema?", correctAnswer: "Memoria RAM." },
  { question: "¿Cuál de los siguientes protocolos cifra la comunicación entre un navegador y un servidor web?", correctAnswer: "HTTPS." },
  { question: "¿Qué entidad regula el espectro radioeléctrico y servicios de internet en Ecuador?", correctAnswer: "ARCOTEL." },
  { question: "¿Qué protocolo permite autenticación sin enviar contraseñas en texto plano?", correctAnswer: "OAuth 2.0" },
  { question: "¿Qué tipo de red utiliza tecnología Bluetooth para conectar dispositivos cercanos?", correctAnswer: "PAN" },
  { question: "Según la Ley de Comercio Electrónico de Ecuador, ¿qué elemento debe incluirse obligatoriamente en un contrato electrónico?", correctAnswer: "La identificación clara del proveedor y los términos del servicio." },
  { question: "¿Qué componente de inteligencia se enfoca en predicciones a largo plazo?", correctAnswer: "Inteligencia estratégica" },
  { question: "¿Cuál de las siguientes fuentes de información es considerada una fuente de inteligencia de amenazas abiertas (OSINT)?", correctAnswer: "Foros públicos, blogs y redes sociales." },
  { question: "¿Qué delito tipifica el COIP por suplantar identidad digital?", correctAnswer: "Art. 177 (Fraude informático)." },
  { question: "¿Qué tipo de evidencia incluye metadatos de archivos?", correctAnswer: "Evidencia digital (ej. propiedades de un PDF)" },
  { question: "¿Qué protocolo opera en la capa de transporte y es orientado a conexión?", correctAnswer: "TCP" },
  { question: "¿Qué vulnerabilidad explota la confianza de un sitio web en el navegador del usuario?", correctAnswer: "CSRF" },
  { question: "¿Qué tipo de dirección IP es 192.168.1.1?", correctAnswer: "Privada" },
  { question: "¿Qué tipo de evidencia se puede obtener de la Memoria RAM durante un análisis forense en vivo?", correctAnswer: "Contraseñas en texto claro, procesos activos y conexiones de red." },
  { question: "¿Qué institución ecuatoriana supervisa el cumplimiento de la LOPDP?", correctAnswer: "Autoridad de Protección de Datos Personales (APDP)." },
  { question: "¿Qué cabecera HTTP ayuda a prevenir el sniffing de MIME types?", correctAnswer: "X-Content-Type-Options: nosniff" },
  { question: "¿Qué tipo de ataque consiste en inundar una red con solicitudes falsas para denegar el servicio a usuarios legítimos?", correctAnswer: "DDoS (Ataque de denegación de servicio)." },
  { question: "¿Qué protocolo es esencial para autenticar servidores web y cifrar conexiones?", correctAnswer: "TLS/SSL" },
  { question: "¿Qué tipo de red tiene direccionalidad en sus conexiones?", correctAnswer: "Red dirigida." },
  { question: "¿Cuál es una ventaja de aplicar inteligencia de amenazas en una organización?", correctAnswer: "Mejorar la capacidad de prevenir y mitigar ciberataques." },
  { question: "¿Qué técnica protege contra ataques de repetición (replay attacks)?", correctAnswer: "Nonces (Números usados una vez)" },
  { question: "¿Qué tipo de token se usa comúnmente para autenticación en APIs modernas?", correctAnswer: "JWT (JSON Web Token)" },
  { question: "¿Qué tipo de ataque busca borrar huellas digitales en un sistema comprometido?", correctAnswer: "Anti-forense" },
  { question: "¿Qué comando en Linux lista archivos ocultos?", correctAnswer: "ls -a" },
  { question: "¿Qué pena puede imponerse por difundir pornografía infantil en línea según el COIP?", correctAnswer: "Hasta 13 años de prisión." },
  { question: "¿Qué tipo de clave es necesaria para el cifrado asimétrico?", correctAnswer: "Ambas (clave pública y privada)" },
  { question: "¿Qué herramienta o estándar se usa para gestionar certificados digitales y autenticación segura en la web?", correctAnswer: "PKI (Infraestructura de Clave Pública." },
  { question: "¿Qué técnica de seguridad oculta datos sensibles en logs o mensajes de error?", correctAnswer: "Masking" },
  { question: "¿Qué herramienta es de gran utilidad para realizar pruebas de penetración en aplicaciones web?", correctAnswer: "BurpSuite." },
  { question: "¿Qué formato de archivo es común para reportes forenses?", correctAnswer: ".pdf o .html" },
  { question: "¿Qué tipo de firewall filtra paquetes basándose en reglas predefinidas?", correctAnswer: "Firewall de red (Packet Filtering)" },
  { question: "¿Qué es la inteligencia de amenazas (Threat Intelligence) en ciberseguridad?", correctAnswer: "El proceso de recopilar, analizar y utilizar información sobre amenazas actuales y futuras." },
  { question: "¿Qué estándar de cifrado es considerado inseguro hoy en día?", correctAnswer: "DES" },
  { question: "¿Qué principio forense asegura que los datos originales no sean alterados durante la investigación?", correctAnswer: "Cadena de custodia." },
  { question: "¿Qué técnica oculta datos dentro de otros archivos (ej. imágenes)?", correctAnswer: "Esteganografía" },
  { question: "¿Qué técnica correlaciona eventos de seguridad para identificar patrones complejos?", correctAnswer: "SIEM" },
  { question: "¿Qué dispositivo amplifica una señal para extender el alcance de una red?", correctAnswer: "Repetidor" },
  { question: "¿Qué norma ecuatoriana regula los derechos de autor en contenidos digitales y software?", correctAnswer: "Código Orgánico de la Economía Social de los Conocimientos (COESC)." },
  { question: "¿Qué tipo de ataque explota vulnerabilidades en consultas SQL para acceder a bases de datos?", correctAnswer: "SQL Injection." },
  { question: "¿Qué tipo de evidencia es un historial de navegación web?", correctAnswer: "Evidencia volátil" },
  { question: "¿Qué componente de seguridad web valida y filtra el tráfico entrante / saliente en un servidor?", correctAnswer: "WAF (Web Application Firewall)." },
  { question: "¿Cuál de las siguientes topologías de red es más tolerante a fallos?", correctAnswer: "Malla" },
  { question: "¿Qué norma exige a las empresas reportar brechas de seguridad de datos?", correctAnswer: "Reglamento a la LOPDP." },
  { question: "¿Qué tipo de ataque permite la ejecución de comandos maliciosos desde el navegador del usuario?", correctAnswer: "Cross-Site-Scripting (XSS)." },
  { question: "¿Cuál de los siguientes es un principio clave para implementar seguridad en una aplicación web?", correctAnswer: "Validar y sanitizar todas las entradas del usuario." },
  { question: "¿Qué es un IoC (Indicador de Compromiso)?", correctAnswer: "Una evidencia observable de que una brecha de seguridad ha ocurrido." },
  { question: "¿Qué herramienta se utiliza comúnmente para el análisis de imágenes de disco en informática forense?", correctAnswer: "Autopsy." },
  { question: "¿Qué artículo de la Ley de Comercio Electrónico regula la publicidad digital?", correctAnswer: "Art. 10 (veracidad y no engaño)." },
  { question: "¿Qué protocolo de la capa de red es responsable de asignar direcciones IP dinámicas en una red?", correctAnswer: "DHCP." },
  { question: "¿Cuál es la primera fase en una metodología de Hacking Ético?", correctAnswer: "Reconocimiento." },
  { question: "¿Qué tipo de informe contiene detalles técnicos sobre una campaña de malware específica?", correctAnswer: "Threat Report" },
  { question: "¿Qué ataque intercepta la comunicación entre dos partes sin su conocimiento?", correctAnswer: "Man-in-the-Middle (MITM)" },
  { question: "¿Qué capa del modelo OSI se encarga del enrutamiento de paquetes?", correctAnswer: "Capa 3 (Red)" },
  { question: "¿Qué estándar se usa para certificados digitales en la web?", correctAnswer: "X.509" },
  { question: "Según la Ley de Telecomunicaciones, ¿qué principio garantiza igual acceso a internet sin discriminación?", correctAnswer: "Neutralidad de la red." },
  { question: "¿Qué herramienta permite escribir reglas para identificar muestras de malware?", correctAnswer: "YARA" },
  { question: "¿Qué tipo de licencia Creative Commons permite uso comercial sin modificaciones?", correctAnswer: "CC BY-ND." },
  { question: "¿Qué técnica protege contraseñas almacenadas mediante funciones irreversibles?", correctAnswer: "Hashing (ej. bcrypt, SHA-256)" },
  { question: "¿Cuál de los siguientes es un ejemplo de inteligencia táctica en ciberseguridad?", correctAnswer: "Direcciones IP maliciosas observadas en ataques recientes." },
  { question: "¿Qué principio evita la modificación de evidencia durante su análisis?", correctAnswer: "Cadena de custodia" },
  { question: "¿Qué herramienta de OSINT permite recopilar información sobre dominios y direcciones IP asociadas a amenazas?", correctAnswer: "VirusTotal." },
  { question: "¿Cuál es la principal diferencia entre un hacker ético y un cracker?", correctAnswer: "Los hackers éticos tienen autorización; los crackers actúan ilegalmente." },
  { question: "¿Qué dispositivo extraíble suele analizarse en casos de filtración de datos?", correctAnswer: "USB o discos externos" },
  { question: "¿Qué cabecera HTTP evita el clickjacking?", correctAnswer: "X-Frame-Options" },
  { question: "¿Qué mide el grado de un nodo en una red no dirigida?", correctAnswer: "La cantidad de conexiones que tiene." },
  { question: "¿Qué técnica de phishing utiliza sitios web falsos que imitan páginas legítimas?", correctAnswer: "Spoofing." },
  { question: "¿Qué comando en Linux muestra las interfaces de red y sus configuraciones?", correctAnswer: "ifconfig" },
  { question: "¿Qué documento registra el manejo de evidencia desde su recolección hasta el juicio?", correctAnswer: "Cadena de custodia" },
  { question: "¿Qué herramienta analiza dominios maliciosos y direcciones IP?", correctAnswer: "VirusTotal" }
];

// === Dedupe: unimos y quitamos repetidas por pregunta normalizada ===
function normalizeText(text) {
  return text.toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "");
}

const questionsMap = new Map();
[...baseQuestions, ...newQuestions].forEach(q => {
  const key = normalizeText(q.question).trim();
  if (!questionsMap.has(key)) questionsMap.set(key, q);
});
const questions = Array.from(questionsMap.values());

// === Render de respuesta principal ===
function showAnswer(q) {
  results.innerHTML = '';
  const box = document.createElement('div');
  box.classList.add('result');
  box.innerHTML = `
    <span class="question"><strong>Pregunta:</strong> ${q.question}</span>
    <div class="separator"></div>
    <span class="answer"><strong>Respuesta:</strong> ${q.correctAnswer}</span>
  `;
  results.appendChild(box);
}

// === Búsqueda en vivo: muestra RESPUESTA inmediata + sugerencias ===
searchInput.addEventListener('input', () => {
  const searchText = normalizeText(searchInput.value);
  results.innerHTML = '';
  if (!searchText) return;

  const matches = questions.filter(q => normalizeText(q.question).includes(searchText));
  if (matches.length) {
    showAnswer(matches[0]); // mejor coincidencia
    const others = matches.slice(1, 8);
    if (others.length) {
      const title = document.createElement('h4');
      title.textContent = 'Otras coincidencias';
      title.style.marginTop = '12px';
      results.appendChild(title);
      others.forEach(q => {
        const sug = document.createElement('div');
        sug.classList.add('result');
        sug.textContent = q.question;
        sug.addEventListener('click', () => showAnswer(q));
        results.appendChild(sug);
      });
    }
  } else {
    results.textContent = 'No se encontraron coincidencias.';
  }
});

// === Botón Buscar: exacto o parcial, siempre muestra RESPUESTA ===
searchButton.addEventListener('click', () => {
  const searchText = normalizeText(searchInput.value);
  results.innerHTML = '';
  if (!searchText) { results.textContent = 'Escribe algo para buscar.'; return; }
  let best = questions.find(q => normalizeText(q.question) === searchText);
  if (!best) best = questions.find(q => normalizeText(q.question).includes(searchText));
  if (best) showAnswer(best);
  else results.textContent = 'No se encontró la pregunta.';
});

// === Botón Limpiar ===
clearButton.addEventListener('click', () => {
  searchInput.value = '';
  results.innerHTML = '';
});

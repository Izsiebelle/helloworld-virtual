(this.webpackJsonpfrontend=this.webpackJsonpfrontend||[]).push([[0],{12:function(e,t,a){e.exports=a.p+"static/media/HelloWorld4.62e76715.png"},23:function(e,t,a){},28:function(e,t,a){e.exports=a(44)},33:function(e,t,a){},34:function(e,t,a){},41:function(e,t,a){},42:function(e,t,a){},43:function(e,t,a){},44:function(e,t,a){"use strict";a.r(t);var n=a(0),r=a.n(n),l=a(24),c=a.n(l),s=(a(33),a(1)),o=a(2),i=a(4),u=a(3),m=a(7),p=a(5),h=(a(34),a(12)),d=a.n(h),E=function(e){Object(i.a)(a,e);var t=Object(u.a)(a);function a(){return Object(s.a)(this,a),t.apply(this,arguments)}return Object(o.a)(a,[{key:"render",value:function(){return r.a.createElement("div",{className:"landingpage"},r.a.createElement("h1",null,'"Hello, World!" Hackathon'),r.a.createElement("img",{className:"landingpage-logo",src:d.a,alt:"hackathon logo"}),r.a.createElement("div",null,r.a.createElement(m.b,{to:"/signin"},r.a.createElement("button",{type:"button ",className:"button landing-btn primary-button upper-case"},"Signin")),r.a.createElement(m.b,{to:"/signup"},r.a.createElement("button",{type:"button ",className:"button landing-btn primary-button upper-case"},"Signup"))))}}]),a}(r.a.Component),b=a(11),f=a.n(b),v=a(14),g=a(26),w=new function e(){Object(s.a)(this,e),Object(g.a)(this,{loading:!0,isLoggedIn:!1,isRegistered:!1,username:""})},y=a(16),j=function(e){Object(i.a)(a,e);var t=Object(u.a)(a);function a(){return Object(s.a)(this,a),t.apply(this,arguments)}return Object(o.a)(a,[{key:"render",value:function(){var e=this;return r.a.createElement("div",{className:"inputField"},r.a.createElement("input",{className:"input",type:this.props.type,placeholder:this.props.placeholder,value:this.props.value,onChange:function(t){return e.props.onChange(t.target.value)}}))}}]),a}(r.a.Component),k=function(e){Object(i.a)(a,e);var t=Object(u.a)(a);function a(){return Object(s.a)(this,a),t.apply(this,arguments)}return Object(o.a)(a,[{key:"render",value:function(){var e=this;return r.a.createElement("div",{className:"submitButton"},r.a.createElement("button",{className:"btn",disabled:this.props.disabled,onClick:function(){return e.props.onClick()}},this.props.text))}}]),a}(r.a.Component),O=(a(23),function(e){Object(i.a)(a,e);var t=Object(u.a)(a);function a(e){var n;return Object(s.a)(this,a),(n=t.call(this,e)).state={username:"",password:"",buttonDisabled:!1},n}return Object(o.a)(a,[{key:"setInputValue",value:function(e,t){t=t.trim(),this.setState(Object(y.a)({},e,t))}},{key:"resetForm",value:function(){this.setState({username:"",password:"",buttonDisabled:!1})}},{key:"doLogin",value:function(){var e=Object(v.a)(f.a.mark((function e(){var t,a;return f.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:if(this.state.username){e.next=2;break}return e.abrupt("return");case 2:if(this.state.password){e.next=4;break}return e.abrupt("return");case 4:return this.setState({buttonDisabled:!0}),e.prev=5,e.next=8,fetch("/login",{method:"post",headers:{Accept:"application/json","Content-Type":"application/json"},body:JSON.stringify({username:this.state.username,password:this.state.password})});case 8:return t=e.sent,e.next=11,t.json();case 11:(a=e.sent)&&a.success?(w.isLoggedIn=!0,w.username=a.username):a&&!1===a.success&&(this.resetForm(),alert(a.msg)),e.next=19;break;case 15:e.prev=15,e.t0=e.catch(5),console.log(e.t0),this.resetForm();case 19:case"end":return e.stop()}}),e,this,[[5,15]])})));return function(){return e.apply(this,arguments)}}()},{key:"render",value:function(){var e=this;return r.a.createElement("div",{className:"loginForm"},"Signin",r.a.createElement(j,{type:"text",placeholder:"username",value:this.state.username?this.state.username:"",onChange:function(t){return e.setInputValue("username",t)}}),r.a.createElement(j,{type:"text",placeholder:"password",value:this.state.password?this.state.password:"",onChange:function(t){return e.setInputValue("password",t)}}),r.a.createElement(k,{text:"Signin",disabled:this.state.buttonDisabled,onClick:function(){return e.doLogin()}}))}}]),a}(r.a.Component)),N=function(e){Object(i.a)(a,e);var t=Object(u.a)(a);function a(){return Object(s.a)(this,a),t.apply(this,arguments)}return Object(o.a)(a,[{key:"render",value:function(){return r.a.createElement("header",{className:"header"},r.a.createElement("img",{className:"logo",src:d.a,alt:"Hackathon Logo"}),r.a.createElement("div",{className:"spacer"}),r.a.createElement("h1",null,"KC Hackathon 2020"))}}]),a}(r.a.Component),C=function(e){Object(i.a)(a,e);var t=Object(u.a)(a);function a(){return Object(s.a)(this,a),t.apply(this,arguments)}return Object(o.a)(a,[{key:"render",value:function(){return r.a.createElement("div",{className:"Menu"},r.a.createElement("div",{className:"btn-group btn-group-lg",role:"group","aria-label":"Basic example"},r.a.createElement(m.b,{to:"/schedule",className:"btn button"},r.a.createElement("button",{type:"button",className:"button primary-button upper-case"},"Schedule")),r.a.createElement(m.b,{to:"/learn",className:"btn button"},r.a.createElement("button",{type:"button",className:"button primary-button upper-case"},"Learn")),r.a.createElement(m.b,{to:"/fun",className:"btn button"},r.a.createElement("button",{type:"button",className:"button primary-button upper-case"},"Fun"))))}}]),a}(r.a.Component),S=function(e){Object(i.a)(a,e);var t=Object(u.a)(a);function a(){return Object(s.a)(this,a),t.apply(this,arguments)}return Object(o.a)(a,[{key:"render",value:function(){return r.a.createElement("div",{className:"Fun"},r.a.createElement("h1",null,"Fun Tab"))}}]),a}(r.a.Component),x=(a(41),function(e){Object(i.a)(a,e);var t=Object(u.a)(a);function a(){return Object(s.a)(this,a),t.apply(this,arguments)}return Object(o.a)(a,[{key:"render",value:function(){var e=this.props.skill;return r.a.createElement("div",{className:"Skill"},r.a.createElement("div",{className:"image-container"},r.a.createElement("img",{src:d.a,alt:"hi"})),r.a.createElement("h2",null,e.name),r.a.createElement("div",{className:"Skill-description"},r.a.createElement("p",null,e.description)),r.a.createElement("div",{className:"Skill-section"},r.a.createElement("h3",{className:"category"},e.category),r.a.createElement("h3",{className:"level"},e.level)))}}]),a}(r.a.Component)),I=(a(42),function(e){Object(i.a)(a,e);var t=Object(u.a)(a);function a(){return Object(s.a)(this,a),t.apply(this,arguments)}return Object(o.a)(a,[{key:"render",value:function(){return r.a.createElement("div",{className:"SkillsList"},this.props.skills.map((function(e){return r.a.createElement(x,{skill:e})})))}}]),a}(r.a.Component)),L=(a(43),{HTML:"HTML",CSS:"CSS",JavaScript:"JavaScript"}),M=function(e){Object(i.a)(a,e);var t=Object(u.a)(a);function a(){return Object(s.a)(this,a),t.apply(this,arguments)}return Object(o.a)(a,[{key:"renderSortByOptions",value:function(){return Object.keys(L).map((function(e){var t=L[e];return r.a.createElement("li",{key:t},e)}))}},{key:"render",value:function(){return r.a.createElement("div",{className:"SearchBar"},r.a.createElement("h1",{className:"section-title"},"Coding Skills"),r.a.createElement("div",{class:"SearchBar-sort-options"},r.a.createElement("ul",null,this.renderSortByOptions())),r.a.createElement("div",{className:"SearchBar-fields"},r.a.createElement("input",{placeholder:"Search Skill"})),r.a.createElement("div",{class:"submit button primary-button"},r.a.createElement("a",null,"Let's Learn")))}}]),a}(r.a.Component),T={imageSrc:{image:d.a},name:"HTML Skeleton",category:"HTML",level:"Beginner",description:"How to set up your basic HTML file."},H=[T,T,T,T,T,T,T,T],_=function(e){Object(i.a)(a,e);var t=Object(u.a)(a);function a(){return Object(s.a)(this,a),t.apply(this,arguments)}return Object(o.a)(a,[{key:"render",value:function(){return r.a.createElement("div",{className:"Learn"},r.a.createElement(M,null),r.a.createElement(I,{skills:H}))}}]),a}(r.a.Component),P=function(e){Object(i.a)(a,e);var t=Object(u.a)(a);function a(){return Object(s.a)(this,a),t.apply(this,arguments)}return Object(o.a)(a,[{key:"render",value:function(){return r.a.createElement("div",{className:"Learn container"},r.a.createElement("table",{class:"table table-hover table-dark"},r.a.createElement("thead",null,r.a.createElement("tr",null,r.a.createElement("th",{scope:"col"},"Time"),r.a.createElement("th",{scope:"col"},"Activity"),r.a.createElement("th",{scope:"col"},"Description"),r.a.createElement("th",{scope:"col"},"Link"))),r.a.createElement("tbody",null,r.a.createElement("tr",null,r.a.createElement("th",{scope:"row"},"9:00 AM"),r.a.createElement("td",null,"Set Up + Team Ice Breakers "),r.a.createElement("td",null,"Chase mice walk on keyboard sniff all the things eat and than sleep on your face. Meeeeouw paw at your fat belly. Ask to go outside and ask to come inside and ask to go outside and ask to come inside hell is other people i could pee on this if i had the energy. My cat stared at me he was sipping his tea, too. "),r.a.createElement("td",null,r.a.createElement("a",{href:"#"},"I Go somewhere"))),r.a.createElement("tr",null,r.a.createElement("th",{scope:"row"},"10:00 AM"),r.a.createElement("td",null,"Kickoff + Introductions"),r.a.createElement("td",null,"Throwup on your pillow give me attention or face the wrath of my claws for jump around on couch, meow constantly until given food, yet spread kitty litter all over house but prance along on top of the garden fence, annoy the neighbor's dog and make it bark, or crash against wall but walk away like nothing happened, a nice warm laptop for me to sit on."),r.a.createElement("td",null,r.a.createElement("a",{href:"#"},"I Go somewhere"))),r.a.createElement("tr",null,r.a.createElement("th",{scope:"row"},"11:00 AM"),r.a.createElement("td",null,"Planning + Work Time with Team"),r.a.createElement("td",null,"Howl on top of tall thing this cat happen now, it was too purr-fect!!! "),r.a.createElement("td",null,r.a.createElement("a",{href:"#"},"I Go somewhere"))),r.a.createElement("tr",null,r.a.createElement("th",{scope:"row"},"12:00 PM"),r.a.createElement("td",null,"Lunch + Q&A"),r.a.createElement("td",null,"Howl on top of tall thing this cat happen now, it was too purr-fect!!! "),r.a.createElement("td",null,r.a.createElement("a",{href:"#"},"I Go somewhere"))),r.a.createElement("tr",null,r.a.createElement("th",{scope:"row"},"1:00 PM"),r.a.createElement("td",null,"Team Work Time"),r.a.createElement("td",null,"Howl on top of tall thing this cat happen now, it was too purr-fect!!! "),r.a.createElement("td",null,r.a.createElement("a",{href:"#"},"I Go somewhere"))),r.a.createElement("tr",null,r.a.createElement("th",{scope:"row"},"2:00 PM"),r.a.createElement("td",null,"Tik Tok Challenge"),r.a.createElement("td",null,"Howl on top of tall thing this cat happen now, it was too purr-fect!!! "),r.a.createElement("td",null,r.a.createElement("a",{href:"#"},"I Go somewhere"))),r.a.createElement("tr",null,r.a.createElement("th",{scope:"row"},"3:00 PM"),r.a.createElement("td",null,"Team Work Time"),r.a.createElement("td",null,"Howl on top of tall thing this cat happen now, it was too purr-fect!!! "),r.a.createElement("td",null,r.a.createElement("a",{href:"#"},"I Go somewhere"))),r.a.createElement("tr",null,r.a.createElement("th",{scope:"row"},"4:00 PM"),r.a.createElement("td",null,"Break Out Session"),r.a.createElement("td",null,"Howl on top of tall thing this cat happen now, it was too purr-fect!!! "),r.a.createElement("td",null,r.a.createElement("a",{href:"#"},"I Go somewhere"))),r.a.createElement("tr",null,r.a.createElement("th",{scope:"row"},"5:00 PM"),r.a.createElement("td",null,"Quiplash"),r.a.createElement("td",null,"Howl on top of tall thing this cat happen now, it was too purr-fect!!! "),r.a.createElement("td",null,r.a.createElement("a",{href:"#"},"I Go somewhere"))),r.a.createElement("tr",null,r.a.createElement("th",{scope:"row"},"6:00 PM"),r.a.createElement("td",null,"Team Work Time"),r.a.createElement("td",null,"Howl on top of tall thing this cat happen now, it was too purr-fect!!! "),r.a.createElement("td",null,r.a.createElement("a",{href:"#"},"I Go somewhere"))),r.a.createElement("tr",null,r.a.createElement("th",{scope:"row"},"7:00 PM"),r.a.createElement("td",null,"Presentations"),r.a.createElement("td",null,"Howl on top of tall thing this cat happen now, it was too purr-fect!!! "),r.a.createElement("td",null,r.a.createElement("a",{href:"#"},"I Go somewhere"))),r.a.createElement("tr",null,r.a.createElement("th",{scope:"row"},"8:00 PM"),r.a.createElement("td",null,"Judging and Prizes"),r.a.createElement("td",null,"Howl on top of tall thing this cat happen now, it was too purr-fect!!! "),r.a.createElement("td",null,r.a.createElement("a",{href:"#"},"I Go somewhere"))))))}}]),a}(r.a.Component),F=function(e){Object(i.a)(a,e);var t=Object(u.a)(a);function a(){return Object(s.a)(this,a),t.apply(this,arguments)}return Object(o.a)(a,[{key:"render",value:function(){return r.a.createElement("div",{className:"Schedule"},r.a.createElement(P,null))}}]),a}(r.a.Component),A=function(e){Object(i.a)(a,e);var t=Object(u.a)(a);function a(){return Object(s.a)(this,a),t.apply(this,arguments)}return Object(o.a)(a,[{key:"render",value:function(){return r.a.createElement(m.a,null,r.a.createElement(N,null),r.a.createElement("div",{className:"App"},r.a.createElement(C,null),r.a.createElement(p.a,{exact:!0,path:"/schedule",component:F}),r.a.createElement(p.a,{exact:!0,path:"/learn",component:_}),r.a.createElement(p.a,{exact:!0,path:"/fun",component:S})))}}]),a}(r.a.Component),B=function(e){Object(i.a)(a,e);var t=Object(u.a)(a);function a(){return Object(s.a)(this,a),t.apply(this,arguments)}return Object(o.a)(a,[{key:"componentDidMount",value:function(){var e=Object(v.a)(f.a.mark((function e(){var t,a;return f.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.prev=0,e.next=3,fetch("/isLoggedIn",{method:"post",headers:{Accept:"application/json","Content-Type":"application/json"}});case 3:return t=e.sent,e.next=6,t.json();case 6:(a=e.sent)&&a.success?(w.loading=!1,w.isLoggedIn=!0,w.username=a.username):(w.loading=!1,w.isLoggedIn=!1),e.next=14;break;case 10:e.prev=10,e.t0=e.catch(0),w.loading=!1,w.isLoggedIn=!1;case 14:case"end":return e.stop()}}),e,null,[[0,10]])})));return function(){return e.apply(this,arguments)}}()},{key:"render",value:function(){return w.loading?r.a.createElement("div",{className:"app"},r.a.createElement("div",{className:"container"},"Loading, Please wait ...")):w.isLoggedIn?r.a.createElement(m.a,null,r.a.createElement("div",{clasName:"container"},r.a.createElement("h1",null,"You are signed in"),r.a.createElement(p.a,{exact:!0,path:"/dashboard",component:A}),r.a.createElement(A,null))):r.a.createElement("div",{className:"signin"},r.a.createElement("div",{className:"container"},r.a.createElement(O,null)))}}]),a}(r.a.Component),G=function(e){Object(i.a)(a,e);var t=Object(u.a)(a);function a(e){var n;return Object(s.a)(this,a),(n=t.call(this,e)).state={first_name:"",last_name:"",username:"",email:"",password:"",isRegestered:!1,buttonDisabled:!1},n}return Object(o.a)(a,[{key:"setInputValue",value:function(e,t){t=t.trim(),this.setState(Object(y.a)({},e,t))}},{key:"resetForm",value:function(){this.setState({first_name:"",last_name:"",username:"",email:"",password:"",buttonDisabled:!1})}},{key:"doRegister",value:function(){var e=Object(v.a)(f.a.mark((function e(){var t,a;return f.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:if(this.state.first_name&&this.state.last_name){e.next=2;break}return e.abrupt("return");case 2:if(this.state.username){e.next=4;break}return e.abrupt("return");case 4:if(this.state.email){e.next=6;break}return e.abrupt("return");case 6:if(this.state.password){e.next=8;break}return e.abrupt("return");case 8:return this.setState({buttonDisabled:!0}),e.prev=9,e.next=12,fetch("/register",{method:"post",headers:{Accept:"application/json","Content-Type":"application/json"},body:JSON.stringify({first_name:this.state.first_name,last_name:this.state.last_name,username:this.state.username,email:this.state.email,password:this.state.password})});case 12:return t=e.sent,e.next=15,t.json();case 15:(a=e.sent)&&a.success?(w.isRegistered=!0,this.setState({isRegestered:!0})):a&&!1===a.success&&(this.resetForm(),alert(a.msg)),e.next=23;break;case 19:e.prev=19,e.t0=e.catch(9),console.log(e.t0),this.resetForm();case 23:case"end":return e.stop()}}),e,this,[[9,19]])})));return function(){return e.apply(this,arguments)}}()},{key:"render",value:function(){var e=this;return r.a.createElement("div",{className:"loginForm"},"Signup",r.a.createElement(j,{type:"text",placeholder:"First name",value:this.state.first_name?this.state.first_name:"",onChange:function(t){return e.setInputValue("first_name",t)}}),r.a.createElement(j,{type:"text",placeholder:"Last name",value:this.state.last_name?this.state.last_name:"",onChange:function(t){return e.setInputValue("last_name",t)}}),r.a.createElement(j,{type:"email",placeholder:"Email",value:this.state.email?this.state.email:"",onChange:function(t){return e.setInputValue("email",t)}}),r.a.createElement(j,{type:"text",placeholder:"username",value:this.state.username?this.state.username:"",onChange:function(t){return e.setInputValue("username",t)}}),r.a.createElement(j,{type:"text",placeholder:"password",value:this.state.password?this.state.password:"",onChange:function(t){return e.setInputValue("password",t)}}),r.a.createElement(k,{text:"Signup",disabled:this.state.buttonDisabled,onClick:function(){return e.doRegister()}}))}}]),a}(r.a.Component),D=function(e){Object(i.a)(a,e);var t=Object(u.a)(a);function a(){return Object(s.a)(this,a),t.apply(this,arguments)}return Object(o.a)(a,[{key:"render",value:function(){return w.loading?r.a.createElement("div",{className:"app"},r.a.createElement("div",{className:"container"},"Loading, Please wait ...")):w.isRegistered?r.a.createElement(m.a,null,r.a.createElement("div",{className:"App"},r.a.createElement(p.a,{exact:!0,path:"/signin",component:B}))):r.a.createElement("div",{className:"signup"},r.a.createElement("div",{className:"container"},r.a.createElement(G,null)))}}]),a}(r.a.Component),V=function(e){Object(i.a)(a,e);var t=Object(u.a)(a);function a(){return Object(s.a)(this,a),t.apply(this,arguments)}return Object(o.a)(a,[{key:"render",value:function(){return r.a.createElement(m.a,null,r.a.createElement("div",{className:"App"},r.a.createElement(p.a,{strict:!0,exact:!0,path:"/",component:E}),r.a.createElement(p.a,{strict:!0,exact:!0,path:"/signin",component:B}),r.a.createElement(p.a,{strict:!0,exact:!0,path:"/signup",component:D}),r.a.createElement(p.a,{strict:!0,exact:!0,path:"/dashboard",component:A})))}}]),a}(r.a.Component);Boolean("localhost"===window.location.hostname||"[::1]"===window.location.hostname||window.location.hostname.match(/^127(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}$/));c.a.render(r.a.createElement(r.a.StrictMode,null,r.a.createElement(V,null)),document.getElementById("root")),"serviceWorker"in navigator&&navigator.serviceWorker.ready.then((function(e){e.unregister()})).catch((function(e){console.error(e.message)}))}},[[28,1,2]]]);
//# sourceMappingURL=main.12fc8995.chunk.js.map
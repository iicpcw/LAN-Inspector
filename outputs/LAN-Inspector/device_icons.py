"""Code-drawn device icons shared by Tk and offline SVG, no font/image dependency."""
import html


def icon_kind(category):
    value=str(category).lower()
    for words,kind in [
        (('防火墙','firewall'),'firewall'),(('零信任','vpn','上网行为','安全网关'),'security_gateway'),(('交换机','switch'),'switch'),(('路由','router','网关'),'router'),
        (('网络设备',),'network'),(('打印','printer'),'printer'),(('服务器','server','nas'),'server'),
        (('手机','iphone','移动设备','android','安卓','ios/ipados'),'phone'),
        (('平板','ipad','tablet'),'tablet'),
        (('电脑','终端','windows','linux','本机','computer','desktop','macos'),'computer')]:
        if kind=='server' and '终端' in value:continue
        if any(word in value for word in words):return kind
    if value.strip()=='ios':return 'phone'
    if value.strip() in ('pc','laptop'):return 'computer'
    return 'unknown'


def shapes(kind):
    if kind=='network':return [('oval',(24,19,48,43)),('line',(28,23,13,9)),('line',(44,23,59,9)),('line',(36,43,36,55)),('rect',(3,2,19,13)),('rect',(53,2,69,13)),('rect',(28,53,44,63))]
    if kind=='security_gateway':return [('polygon',(36,3,63,13,60,39,49,53,36,62,23,53,12,39,9,13)),('rect',(25,29,47,47)),('line',(29,29,29,21,43,21,43,29))]
    if kind=='computer':return [('rect',(9,7,63,43)),('line',(12,37,60,37)),('line',(36,43,36,54)),('line',(23,55,49,55))]
    if kind=='phone':return [('rect',(23,3,49,60)),('line',(31,9,41,9)),('line',(27,49,45,49)),('oval',(34,53,38,57))]
    if kind=='tablet':return [('rect',(14,3,58,60)),('line',(20,9,52,9)),('oval',(34,53,38,57))]
    if kind=='server':return [('rect',(15,3,57,61)),('line',(15,22,57,22)),('line',(15,42,57,42)),('oval',(21,10,26,15)),('oval',(21,29,26,34)),('oval',(21,49,26,54)),('line',(35,12,49,12)),('line',(35,31,49,31)),('line',(35,51,49,51))]
    if kind=='switch':return [('rect',(4,18,68,49))]+[('rect',(10+i*13,29,18+i*13,39)) for i in range(4)]+[('line',(13,13,59,13)),('line',(13,13,20,7)),('line',(59,13,52,7))]
    if kind=='router':return [('rect',(7,29,65,51)),('line',(17,29,13,8)),('line',(55,29,59,8)),('oval',(16,38,20,42)),('line',(31,40,55,40)),('line',(25,17,47,17)),('line',(25,17,31,11)),('line',(47,17,41,23))]
    if kind=='firewall':return [('rect',(8,9,64,55)),('line',(8,24,64,24)),('line',(8,40,64,40)),('line',(26,9,26,24)),('line',(46,9,46,24)),('line',(18,24,18,40)),('line',(38,24,38,40)),('line',(56,24,56,40)),('line',(26,40,26,55)),('line',(46,40,46,55))]
    if kind=='printer':return [('rect',(17,3,55,21)),('rect',(7,21,65,48)),('rect',(19,38,53,60)),('line',(25,46,47,46)),('line',(25,52,47,52)),('oval',(53,27,57,31))]
    return [('polygon',(36,3,64,18,64,47,36,62,8,47,8,18)),('oval',(29,15,43,29)),('line',(36,29,36,40)),('oval',(34,47,38,51))]


def draw_icon(canvas,kind,x,y,scale=1,color='#243b64',tags=()):
    for shape,coords in shapes(kind):
        points=[(x if i%2==0 else y)+v*scale for i,v in enumerate(coords)]
        options=dict(tags=tuple(tags)+('icon:'+kind,),width=max(1,2*scale))
        if shape=='line':canvas.create_line(*points,fill=color,**options)
        elif shape=='polygon':canvas.create_polygon(*points,fill='',outline=color,**options)
        elif shape=='oval':canvas.create_oval(*points,fill='',outline=color,**options)
        else:canvas.create_rectangle(*points,fill='',outline=color,**options)


def svg_icon(kind,x,y,color='#243b64'):
    parts=['<g transform="translate(%s %s)" fill="none" stroke="%s" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'%(x,y,html.escape(color,quote=True))]
    for shape,coords in shapes(kind):
        if shape=='rect':
            a,b,c,d=coords;parts.append('<rect x="%s" y="%s" width="%s" height="%s" rx="2"/>'%(a,b,c-a,d-b))
        elif shape=='oval':
            a,b,c,d=coords;parts.append('<ellipse cx="%s" cy="%s" rx="%s" ry="%s"/>'%((a+c)/2,(b+d)/2,(c-a)/2,(d-b)/2))
        else:parts.append('<polyline points="'+ ' '.join('%s,%s'%(coords[i],coords[i+1]) for i in range(0,len(coords),2)) + (' '+str(coords[0])+','+str(coords[1]) if shape=='polygon' else '')+'"/>')
    return ''.join(parts)+'</g>'

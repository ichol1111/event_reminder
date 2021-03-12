1.一个管理事件的项目，可以插入，删除事件。事件会按时间排序，并附带EDT, 界面很简单，主要重在功能实现。
2.网页使用了ajax来异步获取数据。
3.框架为Flask。使用的数据库为 google cloud datastore。
4.登录时会利用cookie中的nounce到datastore中查询用户的credential是否仍处于有效期，有则直接登录。
5.另外实现了goole login作为第三方登录。用户能使用goolge账号进行登录。
6.具体的细节可以查看https://docs.google.com/document/d/1LrCmIo3ESdh9eQfUPaL-tYMC0LjPU9xZSbERSzcXGOg/edit# lab0到lab3
7.该项目已部署至google appEngine https://gchen43-event-manager.ue.r.appspot.com/

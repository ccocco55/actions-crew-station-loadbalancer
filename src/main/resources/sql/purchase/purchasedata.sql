/*from tbl_member tm join
        view_post_purchase vpp
on tm.id = vpp.member_id
        join tbl_post_section tps
on vpp.id = tps.post_id and vpp.post_status = 'active'
        join view_file_post_section_file vfps
on tps.id = vfps.post_section_id and vfps.image_type = 'main'
*/
select *
from tbl_purchase;

insert into tbl_member (member_name, member_phone, member_email, member_birth, member_password, member_description)
values ('test', '01012341234', 'test@ac.kr', '20000113', '1234', '테스트 데이터 입니다.');

insert into tbl_member (member_name, member_phone, member_email, member_birth, member_password, member_description)
values ('test2', '01012341234', 'test2@ac.kr', '20000113', '1234', '테스트 데이터 입니다.');

insert into tbl_post (post_title, member_id)
values ('test1', 1),
       ('test2', 1),
       ('test3', 2),
       ('test4', 2),
       ('test5', 2),
       ('test6', 1),
       ('test7', 2),
       ('test8', 2),
       ('test9', 2),
       ('test10', 1),
       ('test11', 2),
       ('test12', 2),
       ('test13', 2),
       ('test14', 1);

insert into tbl_post_section (post_content, post_id)
values ('test1', 33),
       ('test2', 34),
       ('test3', 35),
       ('test4', 36),
       ('test5', 37),
       ('test6', 38),
       ('test7', 39),
       ('test8', 40),
       ('test9', 41),
       ('test10', 42),
       ('test11', 43),
       ('test12', 44),
       ('test13', 45),
       ('test14', 46);
select * from tbl_post;
insert into tbl_file(file_origin_name, file_path, file_name)
values ('origin1', 'path1', 'name1'),
       ('origin2', 'path2', 'name2'),
       ('origin3', 'path3', 'name3'),
       ('origin4', 'path4', 'name4'),
       ('origin5', 'path5', 'name5'),
       ('origin6', 'path6', 'name6'),
       ('origin7', 'path7', 'name7'),
       ('origin8', 'path8', 'name8'),
       ('origin9', 'path9', 'name9'),
       ('origin10', 'path10', 'name10'),
       ('origin11', 'path11', 'name11'),
       ('origin12', 'path12', 'name12'),
       ('origin13', 'path13', 'name13'),
       ('origin14', 'path14', 'name14');

insert into tbl_post_section_file(file_id, post_section_id, image_type)
values (1, 1, 'main'),
       (2, 2, 'main'),
       (3, 3, 'main'),
       (4, 4, 'main'),
       (5, 5, 'main'),
       (6, 6, 'main'),
       (7, 7, 'main'),
       (8, 8, 'main'),
       (9, 9, 'main'),
       (10, 10, 'main'),
       (11, 11, 'main'),
       (12, 12, 'main'),
       (13, 13, 'main'),
       (14, 14, 'main');

insert into tbl_purchase (post_id, purchase_limit_time, purchase_product_count, purchase_country,
                          purchase_product_price, purchase_delivery_method)
values (33, 24, 10, '호주', 10000, 'direct'),
       (34, 24, 10, '미국', 10000, 'parcel'),
       (35, 24, 10, '한국', 10000, 'direct'),
       (36, 24, 10, '일본', 10000, 'parcel'),
       (37, 24, 10, '필리핀', 10000, 'direct'),
       (38, 24, 10, '캐나다', 10000, 'parcel'),
       (39, 24, 10, '보라카이', 10000, 'direct'),
       (40, 24, 10, '화와이', 10000, 'parcel'),
       (41, 24, 10, '런던', 10000, 'direct'),
       (42, 24, 10, '영국', 10000, 'parcel'),
       (43, 24, 10, '중국', 10000, 'direct'),
       (44, 24, 10, '대만', 10000, 'parcel'),
       (45, 24, 10, '홍콩', 10000, 'direct'),
       (46, 24, 10, '러시아', 10000, 'parcel');
set timezone = 'Asia/Seoul';
select now();

select purchase_limit_time, created_datetime
from tbl_post p
         join tbl_purchase tp on p.id = tp.post_id
WHERE p.created_datetime + (tp.purchase_limit_time || 'hour')::interval > NOW();
;
select p.created_datetime + (tp.purchase_limit_time || 'hour')::interval, now()
from tbl_post p
         join tbl_purchase tp on p.id = tp.post_id



insert into tbl_file(file_origin_name, file_path, file_name,file_size)
values ('1qweasd123cs.png', '2025/09/25/1qweasd123cs.png', '1qweasd123cs.png',1000),
       ('ansnaxxc.png', '2025/09/25/ansnaxxc.png', 'ansnaxxc.png',1000);


insert into tbl_post_section (post_content, post_id)
values ('multi',1),('multi',1),('multi',1)

select * from tbl_member;

insert into tbl_address(address_zip_code, address_detail, address, member_id)
values (06226,'서울특별시 강남구 역삼동 771','서울특별시 강남구 역삼로 234 (역삼동)',17);


EXPLAIN ANALYZE
select vpp.post_title,
       vpp.purchase_country,
       vpp.purchase_delivery_method,
       vpp.purchase_limit_time,
       vpp.purchase_product_count,
       vpp.purchase_product_price,
       vpp.purchase_delivery_method,
       vpp.created_datetime,
       vpp.updated_datetime,
       tm.id,
       tm.chemistry_score,
       tm.member_name,
       tm.social_img_url,
       vfmf.id as file_id,
       vfmf.file_name,
       vfmf.file_origin_name,
       vfmf.file_path,
       ta.address
from tbl_member tm
         left outer join view_file_member_file vfmf on tm.id = vfmf.member_id
         join view_post_purchase vpp on tm.id = vpp.member_id and vpp.id = 1
                 join tbl_address ta on tm.id = ta.member_id;



EXPLAIN ANALYZE
select *
 from tbl_member tm
        left outer join view_file_member_file vfmf on tm.id = vfmf.member_id
        join view_post_purchase vpp on tm.id = vpp.member_id
        join tbl_address ta on tm.id = ta.member_id;


EXPLAIN ANALYZE
select vpp.id as post_id,
       vpp.post_title,
       vpp.purchase_country,
       vpp.purchase_delivery_method,
       vpp.purchase_limit_time,
       vpp.purchase_product_count,
       vpp.purchase_product_price,
       vpp.purchase_delivery_method,
       vpp.created_datetime,
       vpp.updated_datetime,
       vfps.file_path,
       vfps.file_name,
       tm.member_name,
       tm.chemistry_score
from tbl_member tm join
     view_post_purchase vpp on tm.id = vpp.member_id
                   join tbl_post_section tps on vpp.id = tps.post_id and vpp.post_status = 'active'
                   join view_file_post_section_file vfps on tps.id = vfps.post_section_id and vfps.image_type = 'main'
-- where vpp.created_datetime + (vpp.purchase_limit_time || 'hour')::interval > now()
--   and (
    where vpp.purchase_country like '%' || 'test' || '%'
        or vpp.post_title like '%' || 'test' || '%'
--     )
limit 5 offset 0;

create extension if not exists pg_trgm;/* (최초 1번만)*/
create index idx_member_name_trgm
    on tbl_post
    using gin (post_title gin_trgm_ops);

create index idx_member_test_trgm
    on tbl_purchase
        using gin (purchase_country gin_trgm_ops);







select vpp.id as post_id,
       vpp.post_title,
       vpp.purchase_country,
       vpp.purchase_delivery_method,
       vpp.purchase_limit_time,
       vpp.purchase_product_count,
       vpp.purchase_product_price,
       vpp.purchase_delivery_method,
       vpp.created_datetime,
       vpp.updated_datetime,
       tm.id as member_id,
       tm.chemistry_score,
       tm.member_name,
       tm.social_img_url,
       vfmf.id as file_id,
       vfmf.file_name,
       vfmf.file_origin_name,
       vfmf.file_path,
       ta.address
from tbl_member tm
         left outer join view_file_member_file vfmf on tm.id = vfmf.member_id
         join view_post_purchase vpp on tm.id = vpp.member_id and vpp.id = 3
    join tbl_address ta on tm.id = ta.member_id
where vpp.post_status = 'active'

select * from view_post_purchase;
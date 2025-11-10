create view view_file_member_file as
(
select id,
       file_origin_name,
       file_path,
       file_name,
       created_datetime,
       updated_datetime,
       member_id
from tbl_file tf
         join tbl_member_file tmf on tf.id = tmf.file_id
    );

create view view_file_inquiry_file as
(
select id,
       file_origin_name,
       file_path,
       file_name,
       created_datetime,
       updated_datetime,
       file_size,
       inquiry_id
from tbl_file tf
         join tbl_inquiry_file tif on tf.id = tif.file_id
    );


create view view_file_banner_file as
(
select id,
       file_origin_name,
       file_path,
       file_name,
       created_datetime,
       updated_datetime,
       file_id,
       banner_id
from tbl_file tf
         join tbl_banner_file tbf on tf.id = tbf.file_id
    );

create view view_file_crew_file as
(
select id,
       file_origin_name,
       file_path,
       file_name,
       created_datetime,
       updated_datetime,
       file_id,
       crew_id
from tbl_file tf
         join tbl_crew_file tcf on tf.id = tcf.file_id
    );


create view view_file_post_section_file as
(
select id,
       file_origin_name,
       file_path,
       file_name,
       created_datetime,
       updated_datetime,
       file_id,
       post_section_id,
       image_type,
       file_size
from tbl_file tf
         join tbl_post_section_file tpsf on tf.id = tpsf.file_id
    );


create view view_post_purchase as
(
select id,
       post_title,
       post_read_count,
       post_status,
       member_id,
       created_datetime,
       updated_datetime,
       purchase_product_price,
       purchase_limit_time,
       purchase_product_count,
       purchase_country,
       purchase_delivery_method
from tbl_post tp
         join tbl_purchase tpr on tp.id = tpr.post_id
    );


create view view_post_accompany_accompany_path_country as
(
select tp.id  as post_id,
       post_title,
       post_read_count,
       post_status,
       member_id,
       created_datetime,
       updated_datetime,
       accompany_status,
       accompany_age_range,
       tap.id as accompany_path_id,
       country_start_date,
       country_end_date,
       country_id,
       country_name
from tbl_post tp
         join tbl_accompany ta on tp.id = ta.post_id and post_status = 'active'
         join tbl_accompany_path tap on ta.post_id = tap.accompany_id
         join tbl_country tc on tap.country_id = tc.id
    );



create view view_post_diary as
(
select id,
       post_title,
       post_read_count,
       post_status,
       member_id,
       created_datetime,
       updated_datetime,
       diary_secret,
       diary_like_count,
       diary_reply_count
from tbl_post tp
         join tbl_diary td on tp.id = td.post_id
    );
drop view view_post_diary;


create view view_report_post_report as
(
select id,
       report_content,
       report_process_status,
       member_id,
       created_datetime,
       updated_datetime,
       post_id
from tbl_report tr
         join tbl_post_report tpr on tr.id = tpr.report_id
    );



create view view_report_reply_report as
(
select id,
       report_content,
       report_process_status,
       member_id,
       created_datetime,
       updated_datetime,
       report_id,
       reply_id
from tbl_report tr
         join tbl_reply_report trr on tr.id = trr.report_id
    );



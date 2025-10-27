import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

const REGION = "ap-northeast-2";   // 서울 리전
const TARGET_BUCKET = "fit-bool-p"; // 저장할 버킷 이름 고정

const s3 = new S3Client({ region: REGION });

export const handler = async (event) => {
  try {
    const body = JSON.parse(event.body);
    const originalFileName = body.filename;

    // 최종 저장 경로: s3://fit-bool-p/Upload/filename
    const fileKey = `Upload/${originalFileName}`;

    const command = new PutObjectCommand({
      Bucket: TARGET_BUCKET,
      Key: fileKey,
    });

    const uploadUrl = await getSignedUrl(s3, command, { expiresIn: 3600 });

    return {
      statusCode: 200,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "OPTIONS,POST",
      },
      body: JSON.stringify({
        upload_url: uploadUrl,
        bucket: TARGET_BUCKET,
        file_key: fileKey,
      }),
    };
  } catch (error) {
    console.error("Error generating presigned URL:", error);

    return {
      statusCode: 500,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
      },
      body: JSON.stringify({ message: "Failed to generate URL" }),
    };
  }
};

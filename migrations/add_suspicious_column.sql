-- Add suspicious column to attendance table for photo-mismatch flagging
ALTER TABLE attendance ADD COLUMN IF NOT EXISTS suspicious BOOLEAN DEFAULT FALSE;

-- Add reason for why attendance was marked suspicious
ALTER TABLE attendance ADD COLUMN IF NOT EXISTS suspicious_reason TEXT;

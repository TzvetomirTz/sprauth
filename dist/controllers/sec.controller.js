import { getPublicKeyBase64 } from '../services/sec.service.js';
export const handleGetPublicKeyReq = async (req, res) => {
    res.status(200).json({ publicKey: getPublicKeyBase64() });
};
//# sourceMappingURL=sec.controller.js.map
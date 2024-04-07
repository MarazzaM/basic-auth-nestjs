import { ApiProperty } from '@nestjs/swagger';
export class AuthEntity {
  @ApiProperty()
  backendTokens: {
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
  };
}

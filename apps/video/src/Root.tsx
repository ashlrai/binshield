import { Composition } from "remotion";
import { BinShieldDemo } from "./Demo";

export const RemotionRoot: React.FC = () => {
  return (
    <Composition
      id="BinShieldDemo"
      component={BinShieldDemo}
      durationInFrames={900}
      fps={30}
      width={1920}
      height={1080}
    />
  );
};
